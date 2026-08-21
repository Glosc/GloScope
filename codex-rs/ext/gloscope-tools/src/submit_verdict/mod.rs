//! `submit_verdict` tool: runs a self-contained, read-only-sandboxed `codex
//! exec` sub-agent to deeply verify a single vulnerability candidate. Ported
//! from `legacy-python/gloscope/verify.py`. Never returns a tool error for a
//! failed verification — fail-open into an `inconclusive` [`Verification`]
//! with an `error` string, so one flaky candidate can't abort a scan.

pub(crate) mod spec;

use codex_extension_api::FunctionCallError;
use codex_extension_api::JsonToolOutput;
use codex_extension_api::ToolCall;
use codex_extension_api::ToolExecutor;
use codex_extension_api::ToolExecutorFuture;
use codex_extension_api::ToolName;
use codex_extension_api::ToolOutput;
use codex_gloscope_config::GloscopeConfig;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;
use std::sync::Mutex;

pub use spec::SUBMIT_VERDICT_TOOL_NAME;
use spec::create_submit_verdict_tool;

const PROVIDER_ID: &str = "gloscope";
const ENV_KEY: &str = "GLOSCOPE_API_KEY";
/// dogfood 实测：codex exec 偶发返回空输出，瞬时性问题，重试一次通常能拿到正常输出。
const MAX_RETRIES: u8 = 1;
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Which vulnerability verdict was reached. Mirrors `Verdict` in
/// `legacy-python/gloscope/models.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    Confirmed,
    FalsePositive,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Confidence {
    High,
    Medium,
    Low,
}

/// Where the flagged code actually executes. dogfooding showed this matters:
/// a ReDoS in vendored front-end JS and a server-side one carry very
/// different risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ExecutionContext {
    Server,
    Client,
    Unknown,
}

/// Verification result for one candidate. Mirrors `Verification` in
/// `legacy-python/gloscope/models.py`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Verification {
    pub(crate) verdict: Verdict,
    pub(crate) cwe: String,
    #[serde(default)]
    pub(crate) taint_path: Vec<String>,
    pub(crate) confidence: Confidence,
    #[serde(default)]
    pub(crate) poc_idea: String,
    #[serde(default)]
    pub(crate) explanation: String,
    #[serde(default)]
    pub(crate) poc_method: String,
    #[serde(default)]
    pub(crate) poc_path: String,
    #[serde(default)]
    pub(crate) poc_query: String,
    #[serde(default)]
    pub(crate) poc_body: String,
    #[serde(default)]
    pub(crate) poc_signal: String,
    pub(crate) execution_context: ExecutionContext,
    #[serde(default)]
    pub(crate) error: Option<String>,
    #[serde(default)]
    pub(crate) model: String,
    #[serde(default)]
    pub(crate) tokens_in: u64,
    #[serde(default)]
    pub(crate) tokens_out: u64,
}

/// The `candidate` argument submit_verdict receives on input. Distinct from
/// `run_semgrep::Candidate` (that one is constructed internally and has a
/// `&'static str` source field incompatible with `Deserialize`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CandidateArg {
    pub(crate) check_id: String,
    pub(crate) path: String,
    pub(crate) start_line: u32,
    pub(crate) end_line: u32,
    pub(crate) snippet: String,
    pub(crate) message: String,
    #[serde(default)]
    pub(crate) cwe: Option<String>,
    #[serde(default = "default_category")]
    pub(crate) category: String,
    #[serde(default = "default_source")]
    pub(crate) source: String,
}

fn default_category() -> String {
    "unknown".to_string()
}

fn default_source() -> String {
    "semgrep".to_string()
}

#[derive(Debug, Deserialize)]
struct SubmitVerdictArgs {
    target: String,
    candidate: CandidateArg,
}

/// Process-spawn failure. Mirrors the specific exceptions
/// `CodexVerifier.verify()` catches in the Python port (`TimeoutExpired`,
/// `FileNotFoundError`); everything else fails open into an `inconclusive`
/// [`Verification`] rather than propagating as a tool error.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecError {
    #[error(
        "codex 未安装或不在 PATH：请安装 codex-cli（npm i -g @openai/codex）或用 --codex-path 指定"
    )]
    NotFound,
    #[error("codex exec 超时（>{0:?}）")]
    Timeout(Duration),
    #[error("{0}")]
    Io(String),
}

/// Future returned by a [`ProcessRunner`]: `(exit_code, stdout, stderr)`.
pub(crate) type ProcessOutputFuture =
    Pin<Box<dyn Future<Output = Result<(i32, String, String), ExecError>> + Send>>;

/// Injectable process-spawning seam, mirroring the `Runner` type alias in
/// `legacy-python/gloscope/verify.py` (there: `(argv, cwd, env, timeout,
/// stdin_text) -> (returncode, stdout, stderr)`). Unlike `run_semgrep`'s
/// simpler `ProcessRunner`, this one threads an env-var override map and an
/// optional stdin payload, since the nested `codex exec` call needs both
/// (`CODEX_HOME`/`GLOSCOPE_API_KEY` injection, prompt delivered via stdin).
pub(crate) type ProcessRunner = Arc<
    dyn Fn(Vec<String>, PathBuf, HashMap<String, String>, Duration, Option<String>) -> ProcessOutputFuture
        + Send
        + Sync,
>;

fn default_runner() -> ProcessRunner {
    Arc::new(|argv, cwd, env, timeout_duration, stdin_text| {
        Box::pin(async move {
            spawn_and_collect(&argv, &cwd, &env, timeout_duration, stdin_text.as_deref()).await
        })
    })
}

/// codex `--output-schema` contract for the nested verify sub-agent. Ported
/// verbatim from `legacy-python/gloscope/verify.py::OUTPUT_SCHEMA` — codex's
/// strict-schema mode requires every property `required` and
/// `additionalProperties: false`, so the five `poc_*` fields are flat empty-
/// string-means-n/a strings rather than a nullable nested object.
fn output_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "false_positive", "inconclusive"],
                "description": "confirmed=真实可达漏洞；false_positive=误报；inconclusive=证据不足",
            },
            "cwe": {"type": "string", "description": "CWE 编号，如 CWE-89；未知则空字符串"},
            "taint_path": {
                "type": "array",
                "items": {"type": "string"},
                "description": "污点链每一步，格式 path/to/file.py:42 - 该步说明",
            },
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "poc_idea": {"type": "string", "description": "利用/验证思路；无则空字符串"},
            "explanation": {"type": "string", "description": "结论依据：可达性、净化情况等"},
            "poc_method": {"type": "string", "description": "HTTP 方法，如 GET/POST；不适用为空"},
            "poc_path": {"type": "string", "description": "请求路径，如 /user；不适用为空"},
            "poc_query": {"type": "string", "description": "查询串（不含 ?），如 id=' OR '1'='1"},
            "poc_body": {"type": "string", "description": "请求体（form/JSON 文本）；无则空"},
            "poc_signal": {"type": "string", "description": "差分信号：仅当漏洞被触发时出现在响应中的稳定子串"},
            "execution_context": {
                "type": "string",
                "enum": ["server", "client", "unknown"],
                "description": "缺陷执行位置：server=服务端 Python 代码；client=浏览器端 JS/模板；unknown=无法确定",
            },
        },
        "required": ["verdict", "cwe", "taint_path", "confidence", "poc_idea", "explanation",
                     "poc_method", "poc_path", "poc_query", "poc_body", "poc_signal",
                     "execution_context"],
        "additionalProperties": false,
    })
}

/// Verify-agent prompt template. Ported from
/// `legacy-python/gloscope/verify.py::PROMPT_TEMPLATE`, minus the trailing
/// callgraph/entrypoint-index paragraph — `callgraph.py` is out of v1 port
/// scope, so there is never an "HTTP 入口索引" section to reference.
const PROMPT_TEMPLATE: &str = "你是一名资深 Web 安全审计专家，正在验证一个静态扫描候选是否为真实漏洞。
目标仓库根目录就是你的工作目录（{target}），你已拥有只读的读文件/grep/glob 工具，可自由探索。

方法论（按序执行）：
1. 定位候选：读 {path} 第 {start_line}-{end_line} 行附近源码，确认 sink 存在。
2. 回溯污点来源：source 是否用户可控（HTTP 参数、请求体、header、上传文件名等）。
3. 追踪 source → sink 的完整调用链，检查每一步是否存在有效净化
   （参数化查询、白名单校验、路径规范化+前缀校验、URL host 白名单等）。
4. 判断可达性：路由/入口是否注册、该分支是否可被外部请求触达。
5. 下结论：只有「污点可达且无有效净化」才 confirmed；能证明净化/不可达则 false_positive；
   证据不足（如关键文件缺失）则 inconclusive。
6. 判断执行上下文：缺陷代码运行在服务端（Python，如 Flask/Django 视图函数）还是
   客户端（浏览器执行的 JS、模板文件），无法确定则 unknown——两者风险等级不同。

候选 JSON（来自 semgrep）：
{candidate_json}

输出契约（最终回复必须是且仅是一个符合 schema 的 JSON 对象）：
- verdict: \"confirmed\" | \"false_positive\" | \"inconclusive\"
- cwe: \"CWE-89\" 形式，无法判断则空字符串
- taint_path: 数组，每项 \"path/to/file.py:42 - 该步说明\"，confirmed 时必须给出完整链
- confidence: \"high\" | \"medium\" | \"low\"
- poc_idea: 如何构造请求验证（无则空字符串）
- explanation: 结论依据（可达性、净化情况等）
- poc_method/poc_path/poc_query/poc_body/poc_signal: 若 confirmed 且可远程触发，
  给出最小差分请求规格与信号（signal 选仅在漏洞触发时出现的稳定子串）；否则全空串。
- execution_context: \"server\" | \"client\" | \"unknown\"（缺陷运行位置）";

fn render_prompt(target: &Path, candidate: &CandidateArg) -> Result<String, ExecError> {
    let candidate_json = serde_json::to_string_pretty(candidate)
        .map_err(|err| ExecError::Io(err.to_string()))?;
    Ok(PROMPT_TEMPLATE
        .replace("{target}", &target.display().to_string())
        .replace("{path}", &candidate.path)
        .replace("{start_line}", &candidate.start_line.to_string())
        .replace("{end_line}", &candidate.end_line.to_string())
        .replace("{candidate_json}", &candidate_json))
}

/// Serializes writes to `codex-home/config.toml` (see [`write_codex_home`]):
/// on Windows, concurrent renames onto the same destination path can hit a
/// transient sharing violation, so within this process only one writer
/// touches that file at a time. All concurrent `submit_verdict` calls in a
/// given process write identical content for a given target anyway (same
/// `GloscopeConfig`), so serializing this one short critical section costs
/// nothing but does not need to be `async`-aware.
fn write_codex_home_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Writes/refreshes `~/.gloscope/codex-home/config.toml` with the
/// `model_providers.gloscope` block the nested `codex exec` needs to reach
/// the user's configured provider. Ported from
/// `legacy-python/gloscope/verify.py::_write_codex_home`. Deliberately a
/// persistent directory under the user's home, not a temp dir: codex refuses
/// to create PATH-alias helper binaries under the system temp directory, and
/// this must stay independent of the user's real `~/.codex`.
///
/// Writes via a sibling temp file + rename (guarded by
/// [`write_codex_home_lock`]) rather than a direct truncate-and-write: a
/// nested `codex exec` spawned by one concurrent call must never observe a
/// torn/partial write from another.
fn write_codex_home(cfg: &GloscopeConfig, home_override: Option<&Path>) -> std::io::Result<PathBuf> {
    let home = match home_override {
        Some(path) => path.to_path_buf(),
        None => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gloscope")
            .join("codex-home"),
    };
    std::fs::create_dir_all(&home)?;
    let config_toml = format!(
        "[model_providers.{PROVIDER_ID}]\nname = \"GloScope user provider\"\nbase_url = \"{}\"\nenv_key = \"{ENV_KEY}\"\nwire_api = \"{}\"\n",
        cfg.base_url, cfg.wire_api,
    );
    let final_path = home.join("config.toml");
    let _guard = write_codex_home_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut tmp = tempfile::Builder::new()
        .prefix("config.toml.")
        .suffix(".tmp")
        .tempfile_in(&home)?;
    tmp.write_all(config_toml.as_bytes())?;
    tmp.persist(&final_path).map_err(|err| err.error)?;
    Ok(home)
}

/// Best-effort token-usage extraction from codex's `--json` JSONL event
/// stream. Ported from `legacy-python/gloscope/verify.py::_parse_tokens`:
/// malformed/non-object/missing-usage lines silently contribute nothing, and
/// usage accumulates across multiple `turn.completed` events in one session.
fn parse_tokens(stdout: &str) -> (u64, u64) {
    let mut tokens_in = 0u64;
    let mut tokens_out = 0u64;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(usage) = event.get("usage") else {
            continue;
        };
        if usage.get("input_tokens").is_some() {
            tokens_in += usage.get("input_tokens").and_then(serde_json::Value::as_u64).unwrap_or(0);
            tokens_out += usage.get("output_tokens").and_then(serde_json::Value::as_u64).unwrap_or(0);
        }
    }
    (tokens_in, tokens_out)
}

/// `codex.loads("")` shape: an empty/whitespace-only output file. This is the
/// only failure mode that's transient enough to warrant a single retry (per
/// dogfooding notes in the Python port); a missing file or malformed-but-
/// non-empty content is not retried.
fn is_empty_output(text: &str) -> bool {
    text.trim().is_empty()
}

/// Version-probe result cache: `None` = not yet probed, `Some(Err)` = probe
/// failed (cached; not retried), `Some(Ok)` = cached version string. Mirrors
/// `CodexVerifier._version: str | None` where `""` meant "probe failed" —
/// split into a proper `Result` here since `ToolExecutor::handle` takes
/// `&self` and multiple candidates share one tool instance concurrently.
type VersionCache = Mutex<Option<Result<String, String>>>;

/// Native `submit_verdict` tool: shells out to a `codex` binary resolved via
/// `PATH` to run a self-contained, read-only-sandboxed verification sub-agent
/// per candidate. Ported from `legacy-python/gloscope/verify.py::CodexVerifier`.
pub(crate) struct SubmitVerdictTool {
    /// Overridable for tests; production always resolves via `which::which`.
    codex_path_override: Option<String>,
    timeout: Duration,
    runner: ProcessRunner,
    version: VersionCache,
    /// Overridable for tests, so `cargo test` never touches the developer's
    /// real `~/.gloscope/codex-home` — without this, concurrent tests (now
    /// that `supports_parallel_tool_calls` is true, real usage is concurrent
    /// too) raced on that one shared real path.
    home_override: Option<PathBuf>,
    /// Stable for the lifetime of the owning thread (see [`RunId`] and
    /// `GloscopeToolsExtension::tools()`), so every `submit_verdict` call in
    /// one scan appends to the same `findings.jsonl` run directory. `tools()`
    /// is actually invoked once per sampling *step*, not once per thread —
    /// constructing a fresh id here on every call fragmented one scan across
    /// many single-finding run directories.
    run_id: String,
}

impl SubmitVerdictTool {
    /// Used by `GloscopeToolsExtension::tools()` with a run id resolved once
    /// per thread via the thread-scoped `ExtensionData` store.
    pub(crate) fn with_run_id(run_id: String) -> Self {
        Self {
            codex_path_override: None,
            timeout: Duration::from_secs(600),
            runner: default_runner(),
            version: Mutex::new(None),
            home_override: None,
            run_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_runner(codex_path_override: Option<String>, runner: ProcessRunner) -> Self {
        Self {
            codex_path_override,
            timeout: Duration::from_secs(600),
            runner,
            version: Mutex::new(None),
            home_override: None,
            run_id: generate_run_id(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_home(mut self, home: PathBuf) -> Self {
        self.home_override = Some(home);
        self
    }

    fn resolve_codex_path(&self) -> String {
        if let Some(path) = &self.codex_path_override {
            return path.clone();
        }
        which::which("codex")
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "codex".to_string())
    }

    /// Probes `codex --version` once and caches the outcome. Mirrors
    /// `CodexVerifier._probe_version`: a failed probe is cached too, so a
    /// broken install is reported once per tool instance, not once per
    /// candidate.
    async fn probe_version(&self, codex_path: &str) -> Result<String, String> {
        if let Some(cached) = self.version.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
            return cached;
        }
        let argv = vec![codex_path.to_string(), "--version".to_string()];
        let env: HashMap<String, String> = std::env::vars().collect();
        let outcome = (self.runner)(argv, PathBuf::from("."), env, VERSION_PROBE_TIMEOUT, None).await;
        let result = match outcome {
            Ok((0, stdout, _)) => Ok(stdout.trim().to_string()),
            Ok((code, _, _)) => Err(format!("codex --version 退出码 {code}：codex 安装可能损坏")),
            Err(err) => Err(format!("codex 版本探测失败: {err}")),
        };
        *self.version.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result.clone());
        result
    }

    async fn verify(&self, target: &Path, candidate: &CandidateArg, cfg: &GloscopeConfig) -> Verification {
        let target = match std::fs::canonicalize(target) {
            Ok(path) => path,
            Err(err) => return inconclusive(format!("目标路径无法解析: {err}"), &cfg.verify_model),
        };
        let codex_path = self.resolve_codex_path();
        if let Err(err) = self.probe_version(&codex_path).await {
            return inconclusive(err, &cfg.verify_model);
        }
        self.exec(&codex_path, &target, candidate, cfg).await
    }

    async fn exec(
        &self,
        codex_path: &str,
        target: &Path,
        candidate: &CandidateArg,
        cfg: &GloscopeConfig,
    ) -> Verification {
        let prompt = match render_prompt(target, candidate) {
            Ok(prompt) => prompt,
            Err(err) => return inconclusive(err.to_string(), &cfg.verify_model),
        };
        let codex_home = match write_codex_home(cfg, self.home_override.as_deref()) {
            Ok(home) => home,
            Err(err) => return inconclusive(format!("写入 CODEX_HOME 失败: {err}"), &cfg.verify_model),
        };
        let tmpdir = match tempfile::Builder::new().prefix("gloscope-codex-").tempdir() {
            Ok(dir) => dir,
            Err(err) => return inconclusive(format!("创建临时目录失败: {err}"), &cfg.verify_model),
        };
        let schema_path = tmpdir.path().join("output-schema.json");
        if let Err(err) = std::fs::write(
            &schema_path,
            serde_json::to_string_pretty(&output_schema()).unwrap_or_default(),
        ) {
            return inconclusive(format!("写入 output-schema 失败: {err}"), &cfg.verify_model);
        }
        let out_path = tmpdir.path().join("final.json");
        let argv = vec![
            codex_path.to_string(),
            "exec".to_string(),
            "--ephemeral".to_string(),
            "--skip-git-repo-check".to_string(),
            "--json".to_string(),
            "-s".to_string(),
            "read-only".to_string(),
            "-C".to_string(),
            target.display().to_string(),
            "--output-schema".to_string(),
            schema_path.display().to_string(),
            "-o".to_string(),
            out_path.display().to_string(),
            "-c".to_string(),
            format!("model_provider={PROVIDER_ID}"),
            "-m".to_string(),
            cfg.verify_model.clone(),
            "-".to_string(),
        ];
        let mut env: HashMap<String, String> = std::env::vars().collect();
        env.insert("CODEX_HOME".to_string(), codex_home.display().to_string());
        env.insert(ENV_KEY.to_string(), cfg.api_key.clone());

        let (returncode, stdout, stderr) = match (self.runner)(
            argv.clone(),
            target.to_path_buf(),
            env.clone(),
            self.timeout,
            Some(prompt.clone()),
        )
        .await
        {
            Ok(result) => result,
            Err(ExecError::Timeout(d)) => {
                return inconclusive(format!("codex exec 超时（>{d:?}）"), &cfg.verify_model);
            }
            Err(ExecError::NotFound) => {
                return inconclusive(
                    "codex 未安装或不在 PATH：请安装 codex-cli（npm i -g @openai/codex）或用 --codex-path 指定",
                    &cfg.verify_model,
                );
            }
            Err(ExecError::Io(msg)) => return inconclusive(msg, &cfg.verify_model),
        };

        if returncode != 0 {
            let detail = truncate(&stderr).filter(|s| !s.is_empty()).or_else(|| truncate(&stdout));
            return inconclusive(
                format!(
                    "codex exec 退出码 {returncode}: {}",
                    detail.unwrap_or_default()
                ),
                &cfg.verify_model,
            );
        }

        let (mut tokens_in, mut tokens_out) = parse_tokens(&stdout);
        let mut retries_left = MAX_RETRIES;
        let mut retried = false;
        loop {
            match std::fs::read_to_string(&out_path) {
                Ok(text) if !is_empty_output(&text) => match parse_verdict(&text) {
                    Ok(raw) => {
                        return build_verification(raw, cfg, tokens_in, tokens_out);
                    }
                    Err(err) => {
                        let suffix = if retried { "（已重试一次仍失败）" } else { "" };
                        return inconclusive(format!("验证输出不可解析: {err}{suffix}"), &cfg.verify_model);
                    }
                },
                read_result => {
                    let is_retryable = match &read_result {
                        Ok(text) => is_empty_output(text),
                        Err(_) => false,
                    };
                    if retries_left > 0 && is_retryable {
                        retries_left -= 1;
                        retried = true;
                        match (self.runner)(
                            argv.clone(),
                            target.to_path_buf(),
                            env.clone(),
                            self.timeout,
                            Some(prompt.clone()),
                        )
                        .await
                        {
                            Ok((0, retry_stdout, _)) => {
                                let (ti, to) = parse_tokens(&retry_stdout);
                                tokens_in += ti;
                                tokens_out += to;
                                continue;
                            }
                            Ok((code, retry_stdout, retry_stderr)) => {
                                let detail = truncate(&retry_stderr)
                                    .filter(|s| !s.is_empty())
                                    .or_else(|| truncate(&retry_stdout));
                                return inconclusive(
                                    format!(
                                        "codex exec 退出码 {code}（retry）: {}",
                                        detail.unwrap_or_default()
                                    ),
                                    &cfg.verify_model,
                                );
                            }
                            Err(err) => return inconclusive(err.to_string(), &cfg.verify_model),
                        }
                    }
                    let err_msg = match &read_result {
                        Ok(_) => "输出为空".to_string(),
                        Err(err) => err.to_string(),
                    };
                    let suffix = if retried { "（已重试一次仍失败）" } else { "" };
                    return inconclusive(format!("验证输出不可解析: {err_msg}{suffix}"), &cfg.verify_model);
                }
            }
        }
    }
}

/// One id per thread (see [`crate::extension::GloscopeToolsExtension::tools`]),
/// so every `submit_verdict` call within that scan appends to the same run
/// directory. Millisecond epoch timestamp is unique enough for this purpose
/// and sorts chronologically as a directory name.
pub(crate) fn generate_run_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{millis}")
}

/// Appends this candidate's verdict to `<target>/.gloscope/scans/<run_id>/
/// findings.jsonl`, one JSON object per line. First real implementation of
/// the local-report path described (but never built) in `gloscope-app`'s
/// architecture notes. Best-effort: a write failure here must never fail the
/// `submit_verdict` tool call itself, since the model still needs the
/// verdict back to keep reasoning.
fn append_finding(
    target: &Path,
    run_id: &str,
    candidate: &CandidateArg,
    verification: &Verification,
) -> std::io::Result<()> {
    let dir = target.join(".gloscope").join("scans").join(run_id);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("findings.jsonl");
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    let line = json!({ "candidate": candidate, "verification": verification });
    writeln!(file, "{line}")?;
    Ok(())
}

fn truncate(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(500).collect())
}

fn parse_verdict(text: &str) -> Result<serde_json::Value, String> {
    let raw: serde_json::Value = serde_json::from_str(text).map_err(|err| err.to_string())?;
    let verdict = raw
        .get("verdict")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "缺少 verdict 字段".to_string())?;
    if !matches!(verdict, "confirmed" | "false_positive" | "inconclusive") {
        return Err(format!("非法 verdict: {verdict:?}"));
    }
    Ok(raw)
}

fn build_verification(
    raw: serde_json::Value,
    cfg: &GloscopeConfig,
    tokens_in: u64,
    tokens_out: u64,
) -> Verification {
    let get_str = |key: &str| raw.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let verdict = match raw.get("verdict").and_then(|v| v.as_str()).unwrap_or("inconclusive") {
        "confirmed" => Verdict::Confirmed,
        "false_positive" => Verdict::FalsePositive,
        _ => Verdict::Inconclusive,
    };
    let confidence = match raw.get("confidence").and_then(|v| v.as_str()).unwrap_or("low") {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        _ => Confidence::Low,
    };
    let execution_context = match raw
        .get("execution_context")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
    {
        "server" => ExecutionContext::Server,
        "client" => ExecutionContext::Client,
        _ => ExecutionContext::Unknown,
    };
    let taint_path = raw
        .get("taint_path")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Verification {
        verdict,
        cwe: get_str("cwe"),
        taint_path,
        confidence,
        poc_idea: get_str("poc_idea"),
        explanation: get_str("explanation"),
        poc_method: get_str("poc_method").to_uppercase(),
        poc_path: get_str("poc_path"),
        poc_query: get_str("poc_query"),
        poc_body: get_str("poc_body"),
        poc_signal: get_str("poc_signal"),
        execution_context,
        error: None,
        model: cfg.verify_model.clone(),
        tokens_in,
        tokens_out,
    }
}

impl ToolExecutor<ToolCall> for SubmitVerdictTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(SUBMIT_VERDICT_TOOL_NAME)
    }

    fn spec(&self) -> codex_extension_api::ToolSpec {
        create_submit_verdict_tool()
    }

    /// Each call spawns its own `codex exec` subprocess against its own
    /// tempdir (`tmpdir`/`out_path`/`schema_path` in `exec()`), so N
    /// candidates verified in one model turn are safe to run concurrently —
    /// there is no shared mutable state that requires serialization.
    fn supports_parallel_tool_calls(&self) -> bool {
        true
    }

    fn handle(&self, invocation: ToolCall) -> ToolExecutorFuture<'_> {
        Box::pin(async move {
            let args: SubmitVerdictArgs = serde_json::from_str(invocation.function_arguments()?)
                .map_err(|err| FunctionCallError::RespondToModel(err.to_string()))?;
            let cfg = codex_gloscope_config::load_config()
                .map_err(|err| FunctionCallError::RespondToModel(err.to_string()))?;
            let target = Path::new(&args.target);
            let verification = self.verify(target, &args.candidate, &cfg).await;
            let write_target = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
            if let Err(err) =
                append_finding(&write_target, &self.run_id, &args.candidate, &verification)
            {
                tracing::warn!("failed to append finding to findings.jsonl: {err}");
            }
            let value = serde_json::to_value(&verification)
                .map_err(|err| FunctionCallError::Fatal(err.to_string()))?;
            Ok(Box::new(JsonToolOutput::new(value)) as Box<dyn ToolOutput>)
        })
    }
}

async fn spawn_and_collect(
    argv: &[String],
    cwd: &Path,
    env: &HashMap<String, String>,
    timeout_duration: Duration,
    stdin_text: Option<&str>,
) -> Result<(i32, String, String), ExecError> {
    let [program, rest @ ..] = argv else {
        return Err(ExecError::Io("empty argv".to_string()));
    };
    let mut command = Command::new(program);
    command
        .args(rest)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(if stdin_text.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => return Err(ExecError::NotFound),
        Err(err) => return Err(ExecError::Io(err.to_string())),
    };

    if let Some(text) = stdin_text
        && let Some(mut stdin) = child.stdin.take()
        && let Err(err) = stdin.write_all(text.as_bytes()).await
    {
        return Err(ExecError::Io(err.to_string()));
    }

    match timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )),
        Ok(Err(err)) => Err(ExecError::Io(err.to_string())),
        Err(_) => Err(ExecError::Timeout(timeout_duration)),
    }
}

fn inconclusive(error: impl Into<String>, model: &str) -> Verification {
    Verification {
        verdict: Verdict::Inconclusive,
        cwe: String::new(),
        taint_path: Vec::new(),
        confidence: Confidence::Low,
        poc_idea: String::new(),
        explanation: String::new(),
        poc_method: String::new(),
        poc_path: String::new(),
        poc_query: String::new(),
        poc_body: String::new(),
        poc_signal: String::new(),
        execution_context: ExecutionContext::Unknown,
        error: Some(error.into()),
        model: model.to_string(),
        tokens_in: 0,
        tokens_out: 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use codex_extension_api::ToolSpec;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    /// 测试专用占位值，非真实凭据
    const FAKE_KEY: &str = "fake-key-for-unit-tests";

    fn cfg_fixture() -> GloscopeConfig {
        GloscopeConfig {
            base_url: "https://api.deepseek.com".to_string(),
            api_key: FAKE_KEY.to_string(),
            triage_model: "deepseek-chat".to_string(),
            verify_model: "deepseek-reasoner".to_string(),
            wire_api: "responses".to_string(),
            triage_timeout: Duration::from_secs_f64(60.0),
            verify_timeout: Duration::from_secs_f64(600.0),
        }
    }

    fn cand_fixture() -> CandidateArg {
        CandidateArg {
            check_id: "python.flask.security.insecure-sql-query.insecure-sql-query".to_string(),
            path: "app.py".to_string(),
            start_line: 12,
            end_line: 12,
            snippet: "    run_query(dynamically_built_stmt)".to_string(),
            message: "非参数化 SQL 查询".to_string(),
            cwe: Some("CWE-89".to_string()),
            category: "sql_injection".to_string(),
            source: "semgrep".to_string(),
        }
    }

    fn good_output() -> serde_json::Value {
        json!({
            "verdict": "confirmed",
            "cwe": "CWE-89",
            "taint_path": ["app.py:5 - request.args.get 取参", "app.py:12 - sink"],
            "confidence": "high",
            "poc_idea": "id 参数传特殊构造的输入观察查询结构变化",
            "explanation": "请求参数未经净化直接进入查询构造。",
            "poc_method": "GET",
            "poc_path": "/user",
            "poc_query": "id=' OR '1'='1",
            "poc_body": "",
            "poc_signal": "admin",
            "execution_context": "server",
        })
    }

    #[derive(Debug, Clone, Copy)]
    #[allow(dead_code)] // NotFound mirrors the Python fixture's ENOENT branch; not currently exercised by a v1 test.
    enum FakeExc {
        Timeout,
        NotFound,
    }

    #[derive(Debug, Clone)]
    struct ExecCall {
        argv: Vec<String>,
        #[allow(dead_code)]
        cwd: PathBuf,
        env: HashMap<String, String>,
        #[allow(dead_code)]
        timeout: Duration,
        stdin: Option<String>,
        codex_config: Option<String>,
    }

    /// 模拟 codex：--version 调用返回版本串；exec 调用把 result 写到 -o 文件。
    /// Mirrors `FakeCodexRunner` in `legacy-python/tests/test_verify.py`.
    struct FakeCodexRunner {
        result: serde_json::Value,
        returncode: i32,
        stdout: String,
        stderr: String,
        raise_exc: Option<FakeExc>,
        dont_write: bool,
        version_returncode: i32,
        empty_writes: Mutex<u32>,
        calls: Mutex<Vec<ExecCall>>,
    }

    impl FakeCodexRunner {
        fn new() -> Self {
            Self {
                result: good_output(),
                returncode: 0,
                stdout: String::new(),
                stderr: String::new(),
                raise_exc: None,
                dont_write: false,
                version_returncode: 0,
                empty_writes: Mutex::new(0),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn all_calls(&self) -> Vec<ExecCall> {
            self.calls.lock().expect("lock").clone()
        }

        fn exec_calls(&self) -> Vec<ExecCall> {
            self.all_calls()
                .into_iter()
                .filter(|c| c.argv.iter().any(|a| a == "exec"))
                .collect()
        }

        fn into_runner(self: &Arc<Self>) -> ProcessRunner {
            let this = Arc::clone(self);
            Arc::new(move |argv, cwd, env, timeout_duration, stdin_text| {
                let this = Arc::clone(&this);
                let result = this.respond(argv, cwd, env, timeout_duration, stdin_text);
                Box::pin(async move { result })
            })
        }

        fn respond(
            &self,
            argv: Vec<String>,
            cwd: PathBuf,
            env: HashMap<String, String>,
            timeout_duration: Duration,
            stdin_text: Option<String>,
        ) -> Result<(i32, String, String), ExecError> {
            let is_exec = argv.iter().any(|a| a == "exec");
            if is_exec && let Some(exc) = self.raise_exc {
                return Err(match exc {
                    FakeExc::Timeout => ExecError::Timeout(timeout_duration),
                    FakeExc::NotFound => ExecError::NotFound,
                });
            }
            if argv.iter().any(|a| a == "--version") {
                let out = if self.version_returncode == 0 {
                    "codex-cli 0.147.0".to_string()
                } else {
                    String::new()
                };
                self.calls.lock().expect("lock").push(ExecCall {
                    argv,
                    cwd,
                    env,
                    timeout: timeout_duration,
                    stdin: stdin_text,
                    codex_config: None,
                });
                return Ok((self.version_returncode, out, String::new()));
            }
            // 临时文件在 exec 返回后即销毁，调用时快照其内容
            let codex_config = env.get("CODEX_HOME").map(|home| {
                std::fs::read_to_string(Path::new(home).join("config.toml")).unwrap_or_default()
            });
            if !self.dont_write && let Some(pos) = argv.iter().position(|a| a == "-o") {
                let out_path = PathBuf::from(&argv[pos + 1]);
                let mut empty_writes = self.empty_writes.lock().expect("lock");
                if *empty_writes > 0 {
                    *empty_writes -= 1;
                    let _ = std::fs::write(&out_path, "");
                } else {
                    let _ = std::fs::write(&out_path, self.result.to_string());
                }
            }
            self.calls.lock().expect("lock").push(ExecCall {
                argv,
                cwd,
                env,
                timeout: timeout_duration,
                stdin: stdin_text,
                codex_config,
            });
            Ok((self.returncode, self.stdout.clone(), self.stderr.clone()))
        }
    }

    /// Fresh, isolated `codex-home` dir per test tool instance. `into_path()`
    /// deliberately leaks (skips the `TempDir` drop-cleanup): tests run
    /// concurrently now that `supports_parallel_tool_calls` is true, and a
    /// shared real `~/.gloscope/codex-home` path was racing across them.
    fn unique_test_home() -> PathBuf {
        tempfile::Builder::new()
            .prefix("gloscope-test-codex-home-")
            .tempdir()
            .expect("tempdir")
            .keep()
    }

    fn tool_with_fake(fake: &Arc<FakeCodexRunner>) -> SubmitVerdictTool {
        SubmitVerdictTool::with_runner(Some("codex".to_string()), fake.into_runner())
            .with_home(unique_test_home())
    }

    #[tokio::test]
    async fn test_codex_argv_readonly_sandbox_schema_and_model() {
        let fake = Arc::new(FakeCodexRunner::new());
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        let calls = fake.exec_calls();
        let argv = &calls[0].argv;
        assert_eq!(argv[0], "codex");
        assert!(argv.iter().any(|a| a == "exec"));
        let s_idx = argv.iter().position(|a| a == "-s").expect("has -s");
        assert_eq!(argv[s_idx + 1], "read-only");
        assert!(argv.iter().any(|a| a == "--ephemeral"));
        assert!(argv.iter().any(|a| a == "--skip-git-repo-check"));
        assert!(argv.iter().any(|a| a == "--output-schema"));
        assert!(argv.iter().any(|a| a == "-o"));
        assert!(argv.iter().any(|a| a == "--json"));
        let c_idx = argv.iter().position(|a| a == "-C").expect("has -C");
        let expected_target = tmp.path().canonicalize().expect("canonicalize");
        assert_eq!(argv[c_idx + 1], expected_target.display().to_string());
        let m_idx = argv.iter().position(|a| a == "-m").expect("has -m");
        assert_eq!(argv[m_idx + 1], "deepseek-reasoner");
        assert!(argv.iter().any(|a| a == "-c"));
        assert!(argv.iter().any(|a| a.contains("model_provider=gloscope")));
    }

    #[tokio::test]
    async fn test_codex_home_injects_model_provider_config() {
        let fake = Arc::new(FakeCodexRunner::new());
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        let call = &fake.exec_calls()[0];
        assert_eq!(call.env.get("GLOSCOPE_API_KEY").map(String::as_str), Some(FAKE_KEY));
        let home = PathBuf::from(call.env.get("CODEX_HOME").expect("codex home"));
        let expected_home = tool.home_override.clone().expect("test home override");
        assert_eq!(home, expected_home);
        let cfg_toml = call.codex_config.clone().expect("codex config snapshot");
        let parsed: toml::Value = toml::from_str(&cfg_toml).expect("valid toml");
        let providers = parsed
            .get("model_providers")
            .and_then(|v| v.get("gloscope"))
            .expect("gloscope provider");
        assert_eq!(
            providers.get("base_url").and_then(|v| v.as_str()),
            Some("https://api.deepseek.com")
        );
        assert_eq!(
            providers.get("env_key").and_then(|v| v.as_str()),
            Some("GLOSCOPE_API_KEY")
        );
        assert_eq!(providers.get("wire_api").and_then(|v| v.as_str()), Some("responses"));
        assert!(parsed.get("mcp_servers").is_none());
    }

    #[tokio::test]
    async fn test_prompt_travels_via_stdin_not_argv() {
        let fake = Arc::new(FakeCodexRunner::new());
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let cand = cand_fixture();
        tool.verify(tmp.path(), &cand, &cfg_fixture()).await;
        let call = &fake.exec_calls()[0];
        assert_eq!(call.argv.last().map(String::as_str), Some("-"));
        assert!(!call.argv.iter().any(|a| a.contains(&cand.check_id)));
        let stdin_text = call.stdin.clone().expect("stdin present");
        assert!(stdin_text.contains(&cand.check_id));
        assert!(stdin_text.contains("app.py") && stdin_text.contains("12"));
        assert!(stdin_text.contains("污点"));
        assert!(stdin_text.contains("verdict") && stdin_text.contains("taint_path"));
        assert!(stdin_text.contains("file.py:42"));
    }

    #[test]
    fn test_description_instructs_immediate_fix_on_confirmed() {
        let spec = create_submit_verdict_tool();
        let ToolSpec::Function(tool) = spec else {
            panic!("expected a function tool spec");
        };
        assert!(tool.description.contains("apply_patch"));
        assert!(tool.description.to_lowercase().contains("confirmed"));
    }

    #[test]
    fn test_output_schema_file_strict() {
        let schema = output_schema();
        let required: BTreeSet<String> = schema["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect();
        let expected: BTreeSet<String> = [
            "verdict", "cwe", "taint_path", "confidence", "poc_idea", "explanation",
            "poc_method", "poc_path", "poc_query", "poc_body", "poc_signal", "execution_context",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(required, expected);
        assert_eq!(schema["additionalProperties"], json!(false));
        let verdict_enum: BTreeSet<String> = schema["properties"]["verdict"]["enum"]
            .as_array()
            .expect("enum array")
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect();
        assert_eq!(
            verdict_enum,
            ["confirmed", "false_positive", "inconclusive"].iter().map(ToString::to_string).collect()
        );
        let confidence_enum: BTreeSet<String> = schema["properties"]["confidence"]["enum"]
            .as_array()
            .expect("enum array")
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect();
        assert_eq!(confidence_enum, ["high", "medium", "low"].iter().map(ToString::to_string).collect());
        let context_enum: BTreeSet<String> = schema["properties"]["execution_context"]["enum"]
            .as_array()
            .expect("enum array")
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect();
        assert_eq!(context_enum, ["server", "client", "unknown"].iter().map(ToString::to_string).collect());
        for field in ["poc_method", "poc_path", "poc_query", "poc_body", "poc_signal"] {
            assert_eq!(schema["properties"][field]["type"], json!("string"));
        }
    }

    #[tokio::test]
    async fn test_parses_confirmed_verification_with_tokens() {
        let token_stream = [
            json!({"type": "turn.completed", "usage": {"input_tokens": 5000, "output_tokens": 40}})
                .to_string(),
            r#"{"type": "agent_message", "message": "thinking..."}"#.to_string(),
            json!({
                "type": "turn.completed",
                "usage": {"input_tokens": 3000, "cached_input_tokens": 2800, "output_tokens": 60}
            })
            .to_string(),
        ]
        .join("\n");
        let fake = Arc::new(FakeCodexRunner {
            stdout: token_stream,
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Confirmed);
        assert_eq!(v.cwe, "CWE-89");
        assert_eq!(
            v.taint_path,
            vec!["app.py:5 - request.args.get 取参".to_string(), "app.py:12 - sink".to_string()]
        );
        assert_eq!(v.confidence, Confidence::High);
        assert!(v.poc_idea.contains("id 参数"));
        assert!(v.error.is_none());
        assert_eq!((v.tokens_in, v.tokens_out), (8000, 100));
        assert_eq!(v.model, "deepseek-reasoner");
        assert_eq!(v.poc_method, "GET");
        assert_eq!(v.poc_path, "/user");
        assert_eq!(v.poc_query, "id=' OR '1'='1");
        assert_eq!(v.poc_signal, "admin");
        assert_eq!(v.execution_context, ExecutionContext::Server);
    }

    #[tokio::test]
    async fn test_execution_context_defaults_to_unknown_when_missing() {
        let mut output = good_output();
        output.as_object_mut().expect("object").remove("execution_context");
        let fake = Arc::new(FakeCodexRunner {
            result: output,
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.execution_context, ExecutionContext::Unknown);
    }

    #[tokio::test]
    async fn test_nonzero_exit_is_inconclusive_with_error() {
        let fake = Arc::new(FakeCodexRunner {
            returncode: 1,
            stderr: "model provider error".to_string(),
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Inconclusive);
        assert!(v.error.unwrap_or_default().contains("model provider error"));
    }

    #[tokio::test]
    async fn test_timeout_is_inconclusive() {
        let fake = Arc::new(FakeCodexRunner {
            raise_exc: Some(FakeExc::Timeout),
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Inconclusive);
        assert!(v.error.is_some());
    }

    #[tokio::test]
    async fn test_missing_output_file_is_inconclusive() {
        let fake = Arc::new(FakeCodexRunner {
            dont_write: true,
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Inconclusive);
        assert!(v.error.is_some());
    }

    #[tokio::test]
    async fn test_empty_output_auto_retries_once() {
        let fake = Arc::new(FakeCodexRunner {
            empty_writes: Mutex::new(1),
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Confirmed);
        assert!(v.error.is_none());
        assert_eq!(fake.exec_calls().len(), 2);
    }

    #[tokio::test]
    async fn test_empty_output_still_fails_after_retry() {
        let fake = Arc::new(FakeCodexRunner {
            empty_writes: Mutex::new(99),
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Inconclusive);
        let error = v.error.unwrap_or_default().to_lowercase();
        assert!(error.contains("retry") || error.contains("重试"));
        assert_eq!(fake.exec_calls().len(), 2);
    }

    #[tokio::test]
    async fn test_non_empty_parse_error_does_not_retry() {
        let fake = Arc::new(FakeCodexRunner {
            result: json!({"unexpected": "shape"}),
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Inconclusive);
        assert_eq!(fake.exec_calls().len(), 1);
    }

    #[tokio::test]
    async fn test_bad_output_json_is_inconclusive() {
        let fake = Arc::new(FakeCodexRunner {
            result: json!({"unexpected": "shape"}),
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v.verdict, Verdict::Inconclusive);
        assert!(v.error.is_some());
    }

    #[tokio::test]
    async fn test_version_probe_runs_once_and_blocks_exec_on_failure() {
        let fake = Arc::new(FakeCodexRunner {
            version_returncode: 1,
            ..FakeCodexRunner::new()
        });
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let v1 = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        let v2 = tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(v1.verdict, Verdict::Inconclusive);
        assert!(v1.error.unwrap_or_default().contains("codex --version"));
        assert_eq!(v2.verdict, Verdict::Inconclusive);
        assert!(fake.exec_calls().is_empty());
        let version_calls = fake
            .all_calls()
            .into_iter()
            .filter(|c| c.argv.iter().any(|a| a == "--version"))
            .count();
        assert_eq!(version_calls, 1);
    }

    #[tokio::test]
    async fn test_version_probe_precedes_exec_once() {
        let fake = Arc::new(FakeCodexRunner::new());
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        let all_calls = fake.all_calls();
        let version_calls = all_calls.iter().filter(|c| c.argv.iter().any(|a| a == "--version")).count();
        assert_eq!(version_calls, 1);
        assert_eq!(fake.exec_calls().len(), 2);
        assert_eq!(&all_calls[0].argv[..2], ["codex".to_string(), "--version".to_string()]);
    }

    /// Windows：npm 安装的 codex 是 codex.cmd。真实分支通过 `which::which` 解析，
    /// 单元测试无法安全 monkeypatch 一个全局函数，因此直接验证
    /// `codex_path_override`（生产路径由 `resolve_codex_path` 填充）被原样用作
    /// argv[0] —— 这正是 `which::which` 解析结果最终被使用的方式。
    #[tokio::test]
    async fn test_codex_name_resolved_via_pathext() {
        let fake = Arc::new(FakeCodexRunner::new());
        let tool = SubmitVerdictTool::with_runner(
            Some(r"C:\nodejs\codex.CMD".to_string()),
            fake.into_runner(),
        )
        .with_home(unique_test_home());
        let tmp = TempDir::new().expect("tempdir");
        tool.verify(tmp.path(), &cand_fixture(), &cfg_fixture()).await;
        assert_eq!(fake.exec_calls()[0].argv[0], r"C:\nodejs\codex.CMD");
    }

    #[tokio::test]
    async fn test_target_resolved_to_absolute_path() {
        let fake = Arc::new(FakeCodexRunner::new());
        let tool = tool_with_fake(&fake);
        let tmp = TempDir::new().expect("tempdir");
        let base = tmp.path().canonicalize().expect("canonicalize base");
        std::fs::create_dir(base.join("t")).expect("mkdir t");

        struct CwdGuard(PathBuf);
        impl Drop for CwdGuard {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }
        let guard = CwdGuard(std::env::current_dir().expect("cwd"));
        std::env::set_current_dir(&base).expect("chdir");

        tool.verify(Path::new("t"), &cand_fixture(), &cfg_fixture()).await;
        drop(guard);

        let calls = fake.exec_calls();
        let argv = &calls[0].argv;
        let c_idx = argv.iter().position(|a| a == "-C").expect("has -C");
        let expected = base.join("t");
        assert_eq!(argv[c_idx + 1], expected.display().to_string());
    }

    #[test]
    fn test_append_finding_writes_jsonl_and_appends_on_second_call() {
        let tmp = TempDir::new().expect("tempdir");
        let target = tmp.path();
        let run_id = "test-run-id";
        let candidate = cand_fixture();
        let verification = inconclusive("test error", "deepseek-reasoner");

        append_finding(target, run_id, &candidate, &verification).expect("first append");
        let findings_path = target.join(".gloscope").join("scans").join(run_id).join("findings.jsonl");
        let contents = std::fs::read_to_string(&findings_path).expect("read findings");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("parse line");
        assert_eq!(parsed["candidate"]["checkId"], json!(candidate.check_id));
        assert_eq!(parsed["candidate"]["path"], json!(candidate.path));
        assert_eq!(parsed["verification"]["verdict"], json!("inconclusive"));
        assert_eq!(parsed["verification"]["error"], json!("test error"));

        append_finding(target, run_id, &candidate, &verification).expect("second append");
        let contents = std::fs::read_to_string(&findings_path).expect("read findings again");
        assert_eq!(contents.lines().count(), 2);
    }
}
