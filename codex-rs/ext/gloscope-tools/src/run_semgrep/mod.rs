//! `run_semgrep` tool: wraps `semgrep --json` and parses its output into
//! [`Candidate`] values. Ported from `legacy-python/gloscope/semgrep_runner.py`.

mod candidate;
mod spec;

pub(crate) use candidate::Candidate;

use codex_extension_api::FunctionCallError;
use codex_extension_api::JsonToolOutput;
use codex_extension_api::ToolCall;
use codex_extension_api::ToolExecutor;
use codex_extension_api::ToolExecutorFuture;
use codex_extension_api::ToolName;
use codex_extension_api::ToolOutput;
use serde::Deserialize;
use serde::Serialize;
use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub use spec::RUN_SEMGREP_TOOL_NAME;
use spec::create_run_semgrep_tool;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Bundled blind-spot rules shipped alongside this crate: `auto` misses
/// instance-attribute and `str()`-joined path-traversal shapes (confirmed via
/// CVE replay in the legacy Python pipeline).
static BUNDLED_RULES: &str = include_str!("../../rules/blindspots.yml");

#[derive(Debug, thiserror::Error)]
pub(crate) enum SemgrepError {
    #[error("semgrep 未安装或不在 PATH：请先 `pip install semgrep`")]
    NotFound,
    #[error("semgrep 超时（>{0:?}）")]
    Timeout(Duration),
    #[error("semgrep 退出码 {code}: {detail}")]
    NonZeroExit { code: i32, detail: String },
    #[error("semgrep 输出不是合法 JSON: {0}")]
    InvalidJson(String),
    #[error("{0}")]
    Io(String),
}

impl From<SemgrepError> for FunctionCallError {
    fn from(err: SemgrepError) -> Self {
        FunctionCallError::RespondToModel(err.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct RunSemgrepArgs {
    target: String,
    #[serde(default)]
    paths: Option<Vec<String>>,
    #[serde(default)]
    diff_base: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunSemgrepResponse {
    candidates: Vec<Candidate>,
}

/// Future returned by a [`ProcessRunner`]: `(exit_code, stdout, stderr)`.
pub(crate) type ProcessOutputFuture =
    Pin<Box<dyn Future<Output = Result<(i32, String, String), SemgrepError>> + Send>>;

/// Injectable process-spawning seam, mirroring the `runner` constructor
/// argument in `legacy-python/gloscope/semgrep_runner.py` (there: a plain
/// callable recording `(argv, cwd)`; here: an `Arc<dyn Fn>` since tool
/// executors are shared behind `Arc<dyn ToolExecutor<...>>`). Production
/// always uses [`spawn_and_collect`]; tests inject a fake that records calls
/// and returns canned output, without spawning a real OS process.
pub(crate) type ProcessRunner =
    Arc<dyn Fn(Vec<String>, PathBuf, Duration) -> ProcessOutputFuture + Send + Sync>;

fn default_runner() -> ProcessRunner {
    Arc::new(|argv, cwd, timeout_duration| {
        Box::pin(async move { spawn_and_collect(&argv, &cwd, timeout_duration).await })
    })
}

/// Native `run_semgrep` tool: shells out to a `semgrep` binary resolved via
/// `PATH` and parses its `--json` output into candidates.
pub(crate) struct SemgrepTool {
    /// Overridable for tests; production always resolves via `which::which`.
    semgrep_path_override: Option<String>,
    timeout: Duration,
    runner: ProcessRunner,
}

impl SemgrepTool {
    pub(crate) fn new() -> Self {
        Self {
            semgrep_path_override: None,
            timeout: DEFAULT_TIMEOUT,
            runner: default_runner(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_runner(semgrep_path_override: Option<String>, runner: ProcessRunner) -> Self {
        Self {
            semgrep_path_override,
            timeout: DEFAULT_TIMEOUT,
            runner,
        }
    }

    fn resolve_semgrep_path(&self) -> String {
        if let Some(path) = &self.semgrep_path_override {
            return path.clone();
        }
        which::which("semgrep")
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "semgrep".to_string())
    }
}

impl ToolExecutor<ToolCall> for SemgrepTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(RUN_SEMGREP_TOOL_NAME)
    }

    fn spec(&self) -> codex_extension_api::ToolSpec {
        create_run_semgrep_tool()
    }

    fn handle(&self, invocation: ToolCall) -> ToolExecutorFuture<'_> {
        Box::pin(async move {
            let args: RunSemgrepArgs =
                serde_json::from_str(invocation.function_arguments()?)
                    .map_err(|err| FunctionCallError::RespondToModel(err.to_string()))?;
            if args.diff_base.is_some() && args.paths.as_ref().is_some_and(|p| !p.is_empty()) {
                return Err(FunctionCallError::RespondToModel(
                    "paths 与 diff_base 互斥：显式文件清单与增量模式二选一".to_string(),
                ));
            }
            let candidates = run_semgrep(self, Path::new(&args.target), args.paths, args.diff_base)
                .await
                .map_err(FunctionCallError::from)?;
            let value = serde_json::to_value(RunSemgrepResponse { candidates })
                .map_err(|err| FunctionCallError::Fatal(err.to_string()))?;
            Ok(Box::new(JsonToolOutput::new(value)) as Box<dyn ToolOutput>)
        })
    }
}

/// Which file selection mode to run semgrep in. Mirrors the three mutually
/// exclusive modes in `legacy-python/gloscope/semgrep_runner.py`.
pub(crate) enum ArgvMode {
    /// Whole-repo scan restricted to `*.py`.
    WholeRepo,
    /// Explicit file list (relative to target); no `--include` filter, since
    /// an explicit list is already the user's intent.
    Paths(Vec<String>),
    /// Diff-aware scan: only files changed since `diff_base`, restricted to
    /// `*.py` (the `.py` filtering already happened by the time this is
    /// built).
    DiffFiles(Vec<String>),
}

/// Builds the semgrep argv for a given file-selection mode. Pure function,
/// kept separate from process-spawning so it can be unit-tested without a
/// real semgrep binary.
pub(crate) fn build_argv(semgrep_path: &str, rules_path: &Path, mode: ArgvMode) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        semgrep_path.to_string(),
        "--json".to_string(),
        "--no-git-ignore".to_string(),
        "--config".to_string(),
        "auto".to_string(),
        "--config".to_string(),
        rules_path.display().to_string(),
    ];
    match mode {
        ArgvMode::WholeRepo => {
            argv.push("--include".to_string());
            argv.push("*.py".to_string());
            argv.push(".".to_string());
        }
        ArgvMode::Paths(paths) => {
            argv.extend(paths);
        }
        ArgvMode::DiffFiles(files) => {
            argv.push("--include".to_string());
            argv.push("*.py".to_string());
            argv.extend(files);
        }
    }
    argv
}

async fn run_semgrep(
    tool: &SemgrepTool,
    target: &Path,
    paths: Option<Vec<String>>,
    diff_base: Option<String>,
) -> Result<Vec<Candidate>, SemgrepError> {
    let rules_path = write_bundled_rules_to_temp()?;
    let semgrep_path = tool.resolve_semgrep_path();

    let mode = if let Some(paths) = paths {
        ArgvMode::Paths(paths)
    } else if let Some(diff_base) = diff_base {
        let changed = git_changed_files(tool, target, &diff_base).await?;
        ArgvMode::DiffFiles(changed.into_iter().filter(|f| f.ends_with(".py")).collect())
    } else {
        ArgvMode::WholeRepo
    };
    let argv = build_argv(&semgrep_path, &rules_path, mode);

    let (returncode, stdout, stderr) =
        (tool.runner)(argv, target.to_path_buf(), tool.timeout).await?;
    if returncode != 0 {
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().chars().take(500).collect::<String>()
        } else {
            stdout.trim().chars().take(500).collect::<String>()
        };
        return Err(SemgrepError::NonZeroExit {
            code: returncode,
            detail,
        });
    }

    let data: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|err| SemgrepError::InvalidJson(err.to_string()))?;
    Ok(parse_results(&data, target))
}

fn parse_results(data: &serde_json::Value, target: &Path) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let results = data
        .get("results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for item in &results {
        let check_id = item
            .get("check_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown-rule")
            .to_string();
        let metadata_cwe = candidate::normalize_cwe(
            item.get("extra")
                .and_then(|e| e.get("metadata"))
                .and_then(|m| m.get("cwe")),
        );
        let cwe = match &metadata_cwe {
            Some(cwe) if candidate::category_for_cwe(cwe).is_some() => Some(cwe.clone()),
            _ => candidate::infer_cwe(&check_id)
                .map(std::string::ToString::to_string)
                .or(metadata_cwe),
        };
        let start_line = item
            .get("start")
            .and_then(|s| s.get("line"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32;
        let end_line = item
            .get("end")
            .and_then(|s| s.get("line"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32;
        let path = item
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let extra_lines = item
            .get("extra")
            .and_then(|e| e.get("lines"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let message = item
            .get("extra")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let snippet =
            read_snippet(target, &path, start_line, end_line).unwrap_or(extra_lines);
        let category = candidate::infer_category(&check_id, cwe.as_deref());

        candidates.push(Candidate {
            check_id,
            path,
            start_line,
            end_line,
            snippet,
            message,
            cwe,
            category: category.to_string(),
            source: "semgrep",
        });
    }

    candidates.sort_by(|a, b| a.path.cmp(&b.path).then(a.start_line.cmp(&b.start_line)));
    let mut deduped: Vec<Candidate> = Vec::new();
    for c in candidates {
        let is_dup = c.category != "unknown"
            && deduped.iter().any(|d: &Candidate| {
                c.path == d.path
                    && c.category == d.category
                    && (c.start_line as i64 - d.start_line as i64).abs() <= 3
            });
        if !is_dup {
            deduped.push(c);
        }
    }
    deduped
}

/// `extra.lines` has been observed to return unrelated fixed text; the source
/// file on disk is the source of truth.
fn read_snippet(target: &Path, rel_path: &str, start: u32, end: u32) -> Option<String> {
    if start == 0 || end < start {
        return None;
    }
    let contents = std::fs::read_to_string(target.join(rel_path)).ok()?;
    let lines: Vec<&str> = contents.lines().collect();
    let start_idx = usize::try_from(start).ok()?.checked_sub(1)?;
    let end_idx = usize::try_from(end).ok()?;
    if end_idx <= lines.len() && start_idx < end_idx {
        Some(lines[start_idx..end_idx].join("\n"))
    } else {
        None
    }
}

async fn git_changed_files(
    tool: &SemgrepTool,
    target: &Path,
    base: &str,
) -> Result<Vec<String>, SemgrepError> {
    let git = which::which("git")
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "git".to_string());
    let argv = vec![
        git,
        "-C".to_string(),
        target.display().to_string(),
        "diff".to_string(),
        "--name-only".to_string(),
        "--diff-filter=ACMR".to_string(),
        base.to_string(),
    ];
    let (returncode, stdout, stderr) =
        (tool.runner)(argv, target.to_path_buf(), Duration::from_secs(60)).await?;
    if returncode != 0 {
        return Err(SemgrepError::Io(format!(
            "获取 diff 失败（base={base:?}）: {}",
            stderr.trim().chars().take(300).collect::<String>()
        )));
    }
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

async fn spawn_and_collect(
    argv: &[String],
    cwd: &Path,
    timeout_duration: Duration,
) -> Result<(i32, String, String), SemgrepError> {
    let [program, rest @ ..] = argv else {
        return Err(SemgrepError::Io("empty argv".to_string()));
    };
    let mut command = Command::new(program);
    command
        .args(rest)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => return Err(SemgrepError::NotFound),
        Err(err) => return Err(SemgrepError::Io(err.to_string())),
    };

    match timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )),
        Ok(Err(err)) => Err(SemgrepError::Io(err.to_string())),
        Err(_) => Err(SemgrepError::Timeout(timeout_duration)),
    }
}

fn write_bundled_rules_to_temp() -> Result<PathBuf, SemgrepError> {
    let dir = std::env::temp_dir();
    let path = dir.join("gloscope-blindspots.yml");
    std::fs::write(&path, BUNDLED_RULES).map_err(|err| SemgrepError::Io(err.to_string()))?;
    Ok(path)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use codex_extension_api::NoopTurnItemEmitter;
    use codex_protocol::protocol::TruncationPolicy;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn semgrep_sample() -> serde_json::Value {
        json!({
            "version": "1.98.0",
            "errors": [],
            "results": [
                {
                    "check_id": "python.flask.security.insecure-sql-query.insecure-sql-query",
                    "path": "app.py",
                    "start": {"line": 12, "col": 9},
                    "end": {"line": 12, "col": 61},
                    "extra": {
                        "message": "非参数化 SQL 查询可能包含用户输入",
                        "lines": "    run_query(dynamically_built_stmt)",
                        "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements in SQL"]},
                    },
                },
                {
                    "check_id": "python.requests.security.requests-ssrf.requests-ssrf",
                    "path": "app.py",
                    "start": {"line": 20, "col": 13},
                    "end": {"line": 20, "col": 37},
                    "extra": {
                        "message": "Possible SSRF: request target derived from user input",
                        "lines": "    r = perform_fetch(unvalidated_target)",
                        "metadata": {"cwe": "CWE-918"},
                    },
                },
                {
                    "check_id": "python.lang.security.audit.path-traversal-open.path-traversal-open",
                    "path": "lib/files.py",
                    "start": {"line": 27, "col": 5},
                    "end": {"line": 27, "col": 25},
                    "extra": {
                        "message": "Path traversal: opening path joined with user input",
                        "lines": "    with open(joined_user_path) as f:",
                        "metadata": {},
                    },
                },
            ],
        })
    }

    /// Records every `(argv, cwd)` invocation and returns canned output,
    /// mirroring `FakeRunner` in `legacy-python/tests/test_semgrep.py`.
    struct FakeRunner {
        calls: Mutex<Vec<(Vec<String>, PathBuf)>>,
        outcome: Result<(i32, String, String), String>,
    }

    impl FakeRunner {
        fn ok(stdout: impl Into<String>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outcome: Ok((0, stdout.into(), String::new())),
            })
        }

        fn exit(code: i32, stdout: impl Into<String>, stderr: impl Into<String>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outcome: Ok((code, stdout.into(), stderr.into())),
            })
        }

        fn not_found() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outcome: Err("__not_found__".to_string()),
            })
        }

        fn calls(&self) -> Vec<(Vec<String>, PathBuf)> {
            self.calls.lock().expect("lock").clone()
        }

        fn into_runner(self: &Arc<Self>) -> ProcessRunner {
            let this = Arc::clone(self);
            Arc::new(move |argv, cwd, _timeout| {
                let this = Arc::clone(&this);
                Box::pin(async move {
                    this.calls
                        .lock()
                        .expect("lock")
                        .push((argv.clone(), cwd.clone()));
                    match &this.outcome {
                        Ok((code, stdout, stderr)) => {
                            Ok((*code, stdout.clone(), stderr.clone()))
                        }
                        Err(_) => Err(SemgrepError::NotFound),
                    }
                })
            })
        }
    }

    /// A `FakeRunner` that answers a `git diff` call with a canned changed-file
    /// list and every subsequent call (the semgrep invocation) with canned
    /// semgrep stdout, distinguishing calls by whether `argv` contains `"diff"`.
    struct GitThenSemgrepRunner {
        calls: Mutex<Vec<(Vec<String>, PathBuf)>>,
        git_stdout: String,
        semgrep_outcome: (i32, String, String),
    }

    impl GitThenSemgrepRunner {
        fn new(
            git_stdout: impl Into<String>,
            semgrep_outcome: (i32, impl Into<String>, impl Into<String>),
        ) -> Arc<Self> {
            let (code, stdout, stderr) = semgrep_outcome;
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                git_stdout: git_stdout.into(),
                semgrep_outcome: (code, stdout.into(), stderr.into()),
            })
        }

        fn calls(&self) -> Vec<(Vec<String>, PathBuf)> {
            self.calls.lock().expect("lock").clone()
        }

        fn into_runner(self: &Arc<Self>) -> ProcessRunner {
            let this = Arc::clone(self);
            Arc::new(move |argv, cwd, _timeout| {
                let this = Arc::clone(&this);
                Box::pin(async move {
                    this.calls
                        .lock()
                        .expect("lock")
                        .push((argv.clone(), cwd.clone()));
                    if argv.iter().any(|a| a == "diff") {
                        Ok((0, this.git_stdout.clone(), String::new()))
                    } else {
                        let (code, stdout, stderr) = &this.semgrep_outcome;
                        Ok((*code, stdout.clone(), stderr.clone()))
                    }
                })
            })
        }
    }

    fn tool_with_fake(fake: &Arc<FakeRunner>) -> SemgrepTool {
        SemgrepTool::with_runner(Some("semgrep".to_string()), fake.into_runner())
    }

    fn tool_call(target: &str, paths: Option<Vec<&str>>, diff_base: Option<&str>) -> ToolCall {
        let mut args = serde_json::Map::new();
        args.insert("target".to_string(), json!(target));
        if let Some(paths) = paths {
            args.insert("paths".to_string(), json!(paths));
        }
        if let Some(diff_base) = diff_base {
            args.insert("diff_base".to_string(), json!(diff_base));
        }
        ToolCall {
            turn_id: "turn-1".to_string(),
            call_id: "call-run-semgrep".to_string(),
            tool_name: ToolName::plain(RUN_SEMGREP_TOOL_NAME),
            model: "gpt-test".to_string(),
            codex_turn_metadata: None,
            truncation_policy: TruncationPolicy::Bytes(1024),
            conversation_history: codex_extension_api::ConversationHistory::default(),
            turn_item_emitter: Arc::new(NoopTurnItemEmitter),
            environments: Vec::new(),
            payload: codex_extension_api::ToolPayload::Function {
                arguments: serde_json::Value::Object(args).to_string(),
            },
        }
    }

    /// Test-only mirror of [`Candidate`] with an owned `source` field, since
    /// `Candidate::source` is `&'static str` and cannot be produced by a
    /// generic `Deserialize` impl.
    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CandidateView {
        check_id: String,
        path: String,
        start_line: u32,
        end_line: u32,
        snippet: String,
        #[allow(dead_code)]
        message: String,
        cwe: Option<String>,
        category: String,
        #[allow(dead_code)]
        source: String,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ResponseView {
        candidates: Vec<CandidateView>,
    }

    async fn candidates_from(tool: &SemgrepTool, invocation: ToolCall) -> Vec<CandidateView> {
        let output = tool.handle(invocation.clone()).await.expect("handle ok");
        let value = output.code_mode_result(&invocation.payload);
        let response: ResponseView =
            serde_json::from_value(value).expect("response deserializes");
        response.candidates
    }

    #[tokio::test]
    async fn parses_results_into_candidates() {
        let fake = FakeRunner::ok(semgrep_sample().to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call("target", None, None)).await;

        assert_eq!(cands.len(), 3);
        let first = &cands[0];
        assert_eq!(
            first.check_id,
            "python.flask.security.insecure-sql-query.insecure-sql-query"
        );
        assert_eq!(first.path, "app.py");
        assert_eq!(first.start_line, 12);
        assert_eq!(first.end_line, 12);
        assert_eq!(first.snippet, "    run_query(dynamically_built_stmt)");
        assert_eq!(first.cwe, Some("CWE-89".to_string()));
        assert_eq!(cands[1].cwe, Some("CWE-918".to_string()));
        assert_eq!(cands[2].cwe, Some("CWE-22".to_string()));
    }

    #[tokio::test]
    async fn check_id_category_inference_covers_three_vuln_classes() {
        let fake = FakeRunner::ok(semgrep_sample().to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call("target", None, None)).await;

        assert_eq!(cands[0].category, "sql_injection");
        assert_eq!(cands[1].category, "ssrf");
        assert_eq!(cands[2].category, "path_traversal");
    }

    #[tokio::test]
    async fn argv_contains_json_config_and_target() {
        let fake = FakeRunner::ok(json!({"results": [], "errors": []}).to_string());
        let tool = tool_with_fake(&fake);
        candidates_from(&tool, tool_call("target", None, None)).await;

        let calls = fake.calls();
        let (argv, cwd) = &calls[0];
        assert!(argv.contains(&"--json".to_string()));
        assert!(argv.contains(&"auto".to_string()));
        assert!(argv.contains(&".".to_string()));
        assert!(argv.contains(&"--no-git-ignore".to_string()));
        assert!(argv.iter().any(|a| a.contains("gloscope-blindspots.yml")));
        assert_eq!(cwd, &PathBuf::from("target"));
    }

    #[tokio::test]
    async fn v2_rule_families_map_to_new_categories_and_dedup_adjacent() {
        let sample = json!({
            "results": [
                {"check_id": "python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse",
                 "path": "views.py", "start": {"line": 290}, "end": {"line": 290},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.django.security.injection.command.subprocess-injection.subprocess-injection",
                 "path": "views.py", "start": {"line": 430}, "end": {"line": 430},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use",
                 "path": "views.py", "start": {"line": 431}, "end": {"line": 431},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                 "path": "views.py", "start": {"line": 432}, "end": {"line": 432},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.ssti.security.server-side-template-injection",
                 "path": "views.py", "start": {"line": 995}, "end": {"line": 995},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.lang.security.audit.eval-detected.eval-detected",
                 "path": "views.py", "start": {"line": 1100}, "end": {"line": 1100},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.lang.security.deserialization.pickle.avoid-pickle",
                 "path": "views.py", "start": {"line": 1200}, "end": {"line": 1200},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
            ]
        });
        let fake = FakeRunner::ok(sample.to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call("t", None, None)).await;

        let by_line: std::collections::HashMap<u32, &CandidateView> =
            cands.iter().map(|c| (c.start_line, c)).collect();
        assert_eq!(by_line[&290].category, "xss");
        assert_eq!(by_line[&430].cwe, Some("CWE-78".to_string()));
        let mut lines: Vec<u32> = cands.iter().map(|c| c.start_line).collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![290, 430, 995, 1100, 1200]);
        assert_eq!(by_line[&995].category, "ssti");
        assert_eq!(by_line[&1100].category, "code_injection");
        assert_eq!(by_line[&1200].category, "deserialization");
    }

    #[tokio::test]
    async fn v2_categories_include_regex_dos_and_improper_check() {
        let sample = json!({
            "results": [
                {"check_id": "javascript.lang.security.audit.regex-dos.regex-dos",
                 "path": "static/lib.js", "start": {"line": 10}, "end": {"line": 10},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.lang.security.audit.non-literal-import.non-literal-import",
                 "path": "app.py", "start": {"line": 50}, "end": {"line": 50},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
            ]
        });
        let fake = FakeRunner::ok(sample.to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call("t", None, None)).await;

        let by_line: std::collections::HashMap<u32, &CandidateView> =
            cands.iter().map(|c| (c.start_line, c)).collect();
        assert_eq!(by_line[&10].category, "regex_dos");
        assert_eq!(by_line[&10].cwe, Some("CWE-1333".to_string()));
        assert_eq!(by_line[&50].category, "improper_check");
        assert_eq!(by_line[&50].cwe, Some("CWE-706".to_string()));
    }

    #[tokio::test]
    async fn duplicate_rules_on_same_sink_are_deduped() {
        let sample = json!({
            "results": [
                {"check_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
                 "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
                 "extra": {"message": "flask 版", "lines": "s1", "metadata": {}}},
                {"check_id": "python.django.security.injection.tainted-sql-string.tainted-sql-string",
                 "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
                 "extra": {"message": "django 版", "lines": "s2", "metadata": {}}},
                {"check_id": "python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests",
                 "path": "app.py", "start": {"line": 27}, "end": {"line": 27},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.flask.security.injection.ssrf-requests.ssrf-requests",
                 "path": "app.py", "start": {"line": 28}, "end": {"line": 28},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.django.security.injection.path-traversal.path-traversal-open.path-traversal-open",
                 "path": "app.py", "start": {"line": 35}, "end": {"line": 35},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
                {"check_id": "python.flask.security.audit.path-traversal.path-traversal-open",
                 "path": "app.py", "start": {"line": 80}, "end": {"line": 80},
                 "extra": {"message": "m", "lines": "s", "metadata": {}}},
            ]
        });
        let fake = FakeRunner::ok(sample.to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call("t", None, None)).await;

        let keys: Vec<(String, u32, String)> = cands
            .iter()
            .map(|c| (c.path.clone(), c.start_line, c.category.clone()))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("app.py".to_string(), 19, "sql_injection".to_string()),
                ("app.py".to_string(), 27, "ssrf".to_string()),
                ("app.py".to_string(), 35, "path_traversal".to_string()),
                ("app.py".to_string(), 80, "path_traversal".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn empty_results_yields_empty_list() {
        let fake = FakeRunner::ok(json!({"results": [], "errors": []}).to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call("target", None, None)).await;
        assert!(cands.is_empty());
    }

    #[tokio::test]
    async fn semgrep_missing_is_clear_error() {
        let fake = FakeRunner::not_found();
        let tool = tool_with_fake(&fake);
        let err = tool
            .handle(tool_call("target", None, None))
            .await
            .map(|_| ())
            .expect_err("should error");
        let message = err.to_string();
        assert!(message.contains("未安装"), "unexpected message: {message}");
    }

    #[tokio::test]
    async fn nonzero_exit_is_error_with_stderr() {
        let fake = FakeRunner::exit(2, "", "unknown config");
        let tool = tool_with_fake(&fake);
        let err = tool
            .handle(tool_call("target", None, None))
            .await
            .map(|_| ())
            .expect_err("should error");
        assert!(err.to_string().contains("unknown config"));
    }

    #[tokio::test]
    async fn invalid_json_output_is_error() {
        let fake = FakeRunner::ok("not json at all");
        let tool = tool_with_fake(&fake);
        let err = tool
            .handle(tool_call("target", None, None))
            .await
            .map(|_| ())
            .expect_err("should error");
        assert!(err.to_string().contains("JSON"));
    }

    #[tokio::test]
    async fn snippet_read_from_source_file_not_extra_lines() {
        let tmp = TempDir::new().expect("tempdir");
        let mut lines: Vec<String> = (1..=30).map(|i| format!("line {i}")).collect();
        lines[18] =
            "    query = \"SELECT * FROM users WHERE id = '\" + uid + \"'\"".to_string();
        std::fs::write(tmp.path().join("app.py"), lines.join("\n") + "\n")
            .expect("write app.py");

        let raw = json!({
            "results": [
                {"check_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
                 "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
                 "extra": {"message": "m", "lines": "requires login", "metadata": {}}},
            ]
        });
        let fake = FakeRunner::ok(raw.to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call(&tmp.path().display().to_string(), None, None)).await;

        assert!(cands[0].snippet.contains("SELECT * FROM users"));
        assert_ne!(cands[0].snippet, "requires login");
    }

    #[tokio::test]
    async fn snippet_falls_back_to_extra_lines_when_file_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let raw = json!({
            "results": [
                {"check_id": "r", "path": "gone.py", "start": {"line": 3}, "end": {"line": 3},
                 "extra": {"message": "m", "lines": "fallback snippet", "metadata": {}}},
            ]
        });
        let fake = FakeRunner::ok(raw.to_string());
        let tool = tool_with_fake(&fake);
        let cands = candidates_from(&tool, tool_call(&tmp.path().display().to_string(), None, None)).await;

        assert_eq!(cands[0].snippet, "fallback snippet");
    }

    #[tokio::test]
    async fn diff_base_limits_semgrep_to_changed_files() {
        let fake = GitThenSemgrepRunner::new(
            "app.py\nlib/util.py\n",
            (0, json!({"results": [], "errors": []}).to_string(), ""),
        );
        let tool = SemgrepTool::with_runner(Some("semgrep".to_string()), fake.into_runner());
        candidates_from(&tool, tool_call("t", None, Some("origin/main"))).await;

        let calls = fake.calls();
        assert_eq!(calls.len(), 2, "git diff then semgrep");
        let (git_argv, _) = &calls[0];
        assert!(git_argv.iter().any(|a| a == "diff"));

        let (semgrep_argv, _) = &calls[1];
        let last_cfg = semgrep_argv
            .iter()
            .rposition(|a| a == "--config")
            .expect("has --config");
        assert_eq!(
            &semgrep_argv[last_cfg + 2..],
            &["--include", "*.py", "app.py", "lib/util.py"]
        );
    }

    #[tokio::test]
    async fn diff_base_git_failure_is_clear_error() {
        let fake = FakeRunner::exit(128, "", "not a git repository");
        let tool = tool_with_fake(&fake);
        let err = tool
            .handle(tool_call("t", None, Some("main")))
            .await
            .map(|_| ())
            .expect_err("should error");
        assert!(err.to_string().contains("not a git repository"));
        assert_eq!(fake.calls().len(), 1, "semgrep must not run after git failure");
    }

    #[tokio::test]
    async fn paths_filter_limits_semgrep_to_explicit_files() {
        let fake = FakeRunner::ok(json!({"results": [], "errors": []}).to_string());
        let tool = tool_with_fake(&fake);
        candidates_from(
            &tool,
            tool_call("t", Some(vec!["app.py", "lib/util.py"]), None),
        )
        .await;

        let calls = fake.calls();
        let (argv, _) = &calls[0];
        let last_cfg = argv.iter().rposition(|a| a == "--config").expect("has --config");
        assert_eq!(&argv[last_cfg + 2..], &["app.py", "lib/util.py"]);
    }

    #[tokio::test]
    async fn diff_base_and_paths_are_mutually_exclusive() {
        let fake = FakeRunner::ok(json!({"results": [], "errors": []}).to_string());
        let tool = tool_with_fake(&fake);
        let err = tool
            .handle(tool_call("t", Some(vec!["a.py"]), Some("main")))
            .await
            .map(|_| ())
            .expect_err("should error");
        assert!(err.to_string().contains("paths"));
        assert!(err.to_string().contains("diff_base"));
        assert_eq!(fake.calls().len(), 0, "neither git nor semgrep should run");
    }

    #[tokio::test]
    async fn argv_includes_python_only_by_default() {
        let fake = FakeRunner::ok(json!({"results": [], "errors": []}).to_string());
        let tool = tool_with_fake(&fake);
        candidates_from(&tool, tool_call("t", None, None)).await;

        let calls = fake.calls();
        let (argv, _) = &calls[0];
        let idx = argv.iter().position(|a| a == "--include").expect("has --include");
        assert_eq!(argv[idx + 1], "*.py");
    }

    #[tokio::test]
    async fn paths_mode_skips_include_filter() {
        let fake = FakeRunner::ok(json!({"results": [], "errors": []}).to_string());
        let tool = tool_with_fake(&fake);
        candidates_from(
            &tool,
            tool_call("t", Some(vec!["app.py", "notes.txt"]), None),
        )
        .await;

        let calls = fake.calls();
        let (argv, _) = &calls[0];
        assert!(!argv.contains(&"--include".to_string()));
    }

    #[test]
    fn build_argv_whole_repo_mode() {
        let argv = build_argv("semgrep", Path::new("/rules.yml"), ArgvMode::WholeRepo);
        assert!(argv.contains(&"--include".to_string()));
        assert!(argv.contains(&"*.py".to_string()));
        assert!(argv.contains(&".".to_string()));
    }

    #[test]
    fn build_argv_paths_mode_has_no_include_filter() {
        let argv = build_argv(
            "semgrep",
            Path::new("/rules.yml"),
            ArgvMode::Paths(vec!["app.py".to_string()]),
        );
        assert!(!argv.contains(&"--include".to_string()));
        assert!(argv.contains(&"app.py".to_string()));
    }
}
