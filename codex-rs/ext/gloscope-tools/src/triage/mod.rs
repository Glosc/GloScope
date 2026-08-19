//! `triage` tool: a single cheap chat-completion call that decides whether a
//! candidate is worth a deep `submit_verdict` pass. Ported from
//! `legacy-python/gloscope/triage.py`. Fail-open: any failure (bad endpoint,
//! non-200, malformed JSON) returns `keep=true` with an explanatory reason,
//! never a tool error — a single flaky candidate must not silently drop a
//! real vulnerability.

mod spec;

use crate::config;
use crate::config::GloscopeConfig;
use crate::submit_verdict::CandidateArg;
use codex_extension_api::FunctionCallError;
use codex_extension_api::JsonToolOutput;
use codex_extension_api::ToolCall;
use codex_extension_api::ToolExecutor;
use codex_extension_api::ToolExecutorFuture;
use codex_extension_api::ToolName;
use codex_extension_api::ToolOutput;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub use spec::TRIAGE_TOOL_NAME;
use spec::create_triage_tool;

const PROMPT_TEMPLATE: &str = "你是一名漏洞分诊专家。下面是静态扫描（semgrep）产出的一个候选，
请判断它是否【值得】交给深度验证 agent 追污点链（而不是明显误报）。

判断要点：
- 候选代码是否真的存在把外部输入导向危险 sink 的模式；
- 明显的误报（常量拼接、经过参数化/白名单、测试代码等）应当 drop；
- 拿不准的保留（keep），深度验证层会给出最终结论。

候选 JSON：
{candidate_json}

只输出严格 JSON，不要多余文本：{{\"keep\": <true|false>, \"reason\": \"<一行中文理由>\"}}";

fn render_prompt(candidate: &CandidateArg) -> String {
    let candidate_json = serde_json::to_string_pretty(candidate).unwrap_or_default();
    PROMPT_TEMPLATE.replace("{candidate_json}", &candidate_json)
}

/// `base_url` 已带版本段（`/v1`、`/v2`…）则不再补 `/v1`；少数网关路径自定义，不做更多猜测。
pub(crate) fn chat_completions_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if base.ends_with("/chat/completions") {
        return base.to_string();
    }
    let has_version_suffix = base
        .rsplit('/')
        .next()
        .map(|last| {
            last.len() > 1
                && last.starts_with('v')
                && last[1..].chars().all(|c| c.is_ascii_digit())
        })
        .unwrap_or(false);
    if has_version_suffix {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TriageResult {
    pub(crate) keep: bool,
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) model: String,
    #[serde(default)]
    pub(crate) tokens_in: u64,
    #[serde(default)]
    pub(crate) tokens_out: u64,
}

fn fail_open(reason: impl std::fmt::Display, model: &str) -> TriageResult {
    TriageResult {
        keep: true,
        reason: format!("triage failed（已保守保留）: {reason}"),
        model: model.to_string(),
        tokens_in: 0,
        tokens_out: 0,
    }
}

#[derive(Debug, Deserialize)]
struct TriageArgs {
    target: String,
    candidate: CandidateArg,
}

/// One HTTP round trip: `(url, bearer_token, body) -> (status, response_text)`.
/// Mirrors the `HTTP` type alias in `legacy-python/gloscope/triage.py`,
/// injectable so tests never make a real network call.
pub(crate) type HttpFuture = Pin<Box<dyn Future<Output = Result<(u16, String), String>> + Send>>;
pub(crate) type HttpCaller =
    Arc<dyn Fn(String, String, serde_json::Value, Duration) -> HttpFuture + Send + Sync>;

fn default_http_caller() -> HttpCaller {
    Arc::new(|url, bearer_token, body, timeout_duration| {
        Box::pin(async move { real_http(url, bearer_token, body, timeout_duration).await })
    })
}

async fn real_http(
    url: String,
    bearer_token: String,
    body: serde_json::Value,
    timeout_duration: Duration,
) -> Result<(u16, String), String> {
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(bearer_token)
        .json(&body)
        .timeout(timeout_duration)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let text = response.text().await.map_err(|err| err.to_string())?;
    Ok((status, text))
}

pub(crate) struct TriageTool {
    http: HttpCaller,
}

impl TriageTool {
    pub(crate) fn new() -> Self {
        Self {
            http: default_http_caller(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_http(http: HttpCaller) -> Self {
        Self { http }
    }

    async fn triage(&self, candidate: &CandidateArg, cfg: &GloscopeConfig) -> TriageResult {
        match self.call(candidate, cfg).await {
            Ok(result) => result,
            Err(err) => fail_open(err, &cfg.triage_model),
        }
    }

    async fn call(&self, candidate: &CandidateArg, cfg: &GloscopeConfig) -> Result<TriageResult, String> {
        let prompt = render_prompt(candidate);
        let body = json!({
            "model": cfg.triage_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        });
        let url = chat_completions_url(&cfg.base_url);
        let (status, text) = (self.http)(url, cfg.api_key.clone(), body, cfg.triage_timeout)
            .await
            .map_err(|err| err)?;
        if status != 200 {
            let truncated: String = text.chars().take(200).collect();
            return Err(format!("HTTP {status}: {truncated}"));
        }
        let data: serde_json::Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
        let content = data["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| "响应缺少 choices[0].message.content".to_string())?;
        let fenced = strip_fences(content.trim());
        let parsed: serde_json::Value =
            serde_json::from_str(&fenced).map_err(|err| err.to_string())?;
        let keep = parsed
            .get("keep")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| "响应缺少 keep 字段".to_string())?;
        let reason = parsed
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let usage = data.get("usage").cloned().unwrap_or(json!({}));
        let tokens_in = usage.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        let tokens_out = usage.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(TriageResult {
            keep,
            reason,
            model: cfg.triage_model.clone(),
            tokens_in,
            tokens_out,
        })
    }
}

/// Strips a leading/trailing ```` ```json ```` or ```` ``` ```` fence, if present.
fn strip_fences(text: &str) -> String {
    let mut s = text;
    if let Some(rest) = s.strip_prefix("```json") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("```") {
        s = rest;
    }
    if let Some(rest) = s.strip_suffix("```") {
        s = rest;
    }
    s.trim().to_string()
}

impl ToolExecutor<ToolCall> for TriageTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(TRIAGE_TOOL_NAME)
    }

    fn spec(&self) -> codex_extension_api::ToolSpec {
        create_triage_tool()
    }

    /// Each call is an independent HTTP round trip with no shared mutable
    /// state (no filesystem writes, unlike `submit_verdict`), so triaging N
    /// candidates in one model turn is safe to run concurrently.
    fn supports_parallel_tool_calls(&self) -> bool {
        true
    }

    fn handle(&self, invocation: ToolCall) -> ToolExecutorFuture<'_> {
        Box::pin(async move {
            let args: TriageArgs = serde_json::from_str(invocation.function_arguments()?)
                .map_err(|err| FunctionCallError::RespondToModel(err.to_string()))?;
            let cfg = config::load_config(std::path::Path::new(&args.target))
                .map_err(|err| FunctionCallError::RespondToModel(err.to_string()))?;
            let result = self.triage(&args.candidate, &cfg).await;
            let value = serde_json::to_value(result)
                .map_err(|err| FunctionCallError::Fatal(err.to_string()))?;
            Ok(Box::new(JsonToolOutput::new(value)) as Box<dyn ToolOutput>)
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;

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

    #[derive(Debug, Clone)]
    struct RecordedCall {
        url: String,
        bearer_token: String,
        body: serde_json::Value,
        #[allow(dead_code)] // recorded for parity with the Python fixture; not asserted on yet.
        timeout: Duration,
    }

    enum FakeOutcome {
        Ok { status: u16, content: String, usage: (u64, u64) },
        Err(String),
    }

    struct FakeHttp {
        outcome: FakeOutcome,
        last: Mutex<Option<RecordedCall>>,
    }

    impl FakeHttp {
        fn ok(content: &str) -> Self {
            Self {
                outcome: FakeOutcome::Ok {
                    status: 200,
                    content: content.to_string(),
                    usage: (10, 5),
                },
                last: Mutex::new(None),
            }
        }

        fn status(status: u16, content: &str) -> Self {
            Self {
                outcome: FakeOutcome::Ok {
                    status,
                    content: content.to_string(),
                    usage: (0, 0),
                },
                last: Mutex::new(None),
            }
        }

        fn err(message: &str) -> Self {
            Self {
                outcome: FakeOutcome::Err(message.to_string()),
                last: Mutex::new(None),
            }
        }

        fn last_call(&self) -> RecordedCall {
            self.last.lock().expect("lock").clone().expect("a call was made")
        }

        fn into_caller(self: &Arc<Self>) -> HttpCaller {
            let this = Arc::clone(self);
            Arc::new(move |url, bearer_token, body, timeout_duration| {
                let this = Arc::clone(&this);
                *this.last.lock().expect("lock") = Some(RecordedCall {
                    url: url.clone(),
                    bearer_token: bearer_token.clone(),
                    body: body.clone(),
                    timeout: timeout_duration,
                });
                let result = match &this.outcome {
                    FakeOutcome::Ok { status, content, usage } => {
                        let payload = json!({
                            "choices": [{"message": {"content": content}}],
                            "usage": {"prompt_tokens": usage.0, "completion_tokens": usage.1},
                        });
                        Ok((*status, payload.to_string()))
                    }
                    FakeOutcome::Err(message) => Err(message.clone()),
                };
                Box::pin(async move { result })
            })
        }
    }

    fn tool_with_fake(fake: &Arc<FakeHttp>) -> TriageTool {
        TriageTool::with_http(fake.into_caller())
    }

    #[tokio::test]
    async fn test_request_shape_and_url_normalization() {
        let fake = Arc::new(FakeHttp::ok(r#"{"keep": false, "reason": "明显误报"}"#));
        let tool = tool_with_fake(&fake);
        tool.triage(&cand_fixture(), &cfg_fixture()).await;
        let call = fake.last_call();
        assert_eq!(call.url, "https://api.deepseek.com/v1/chat/completions");
        assert_eq!(call.bearer_token, FAKE_KEY);
        assert_eq!(call.body["model"], json!("deepseek-chat"));
        let prompt = call.body["messages"][0]["content"].as_str().expect("content");
        assert!(prompt.contains("python.flask.security.insecure-sql-query.insecure-sql-query"));
        assert!(prompt.contains("app.py"));
        assert!(prompt.contains("12"));
        assert!(prompt.contains("JSON"));
    }

    #[tokio::test]
    async fn test_url_with_explicit_v1_not_duplicated() {
        let fake = Arc::new(FakeHttp::ok(r#"{"keep": true, "reason": "ok"}"#));
        let tool = tool_with_fake(&fake);
        let mut cfg = cfg_fixture();
        cfg.base_url = "https://x.example/v1".to_string();
        tool.triage(&cand_fixture(), &cfg).await;
        assert_eq!(fake.last_call().url, "https://x.example/v1/chat/completions");
    }

    #[tokio::test]
    async fn test_parses_keep_drop_with_usage() {
        let fake = Arc::new(FakeHttp::ok(r#"{"keep": false, "reason": "常量拼接，无用户输入"}"#));
        let tool = tool_with_fake(&fake);
        let r = tool.triage(&cand_fixture(), &cfg_fixture()).await;
        assert!(!r.keep);
        assert_eq!(r.reason, "常量拼接，无用户输入");
        assert_eq!(r.model, "deepseek-chat");
        assert_eq!((r.tokens_in, r.tokens_out), (10, 5));
    }

    #[tokio::test]
    async fn test_strips_markdown_fences() {
        let fake = Arc::new(FakeHttp::ok("```json\n{\"keep\": true, \"reason\": \"需要深查\"}\n```"));
        let tool = tool_with_fake(&fake);
        let r = tool.triage(&cand_fixture(), &cfg_fixture()).await;
        assert!(r.keep);
        assert_eq!(r.reason, "需要深查");
    }

    #[tokio::test]
    async fn test_bad_content_json_fails_open_to_keep() {
        let fake = Arc::new(FakeHttp::ok("I think this is a real issue"));
        let tool = tool_with_fake(&fake);
        let r = tool.triage(&cand_fixture(), &cfg_fixture()).await;
        assert!(r.keep);
        assert!(r.reason.contains("triage failed"));
    }

    #[tokio::test]
    async fn test_http_error_fails_open_to_keep() {
        let fake = Arc::new(FakeHttp::status(500, "boom"));
        let tool = tool_with_fake(&fake);
        let r = tool.triage(&cand_fixture(), &cfg_fixture()).await;
        assert!(r.keep);
        assert!(r.reason.contains("triage failed"));
    }

    #[tokio::test]
    async fn test_timeout_fails_open_to_keep() {
        let fake = Arc::new(FakeHttp::err("read timeout"));
        let tool = tool_with_fake(&fake);
        let r = tool.triage(&cand_fixture(), &cfg_fixture()).await;
        assert!(r.keep);
        assert!(r.reason.contains("triage failed"));
    }

    #[test]
    fn test_url_tolerates_versioned_and_full_endpoints() {
        assert_eq!(
            chat_completions_url("https://x.example/v2"),
            "https://x.example/v2/chat/completions"
        );
        assert_eq!(
            chat_completions_url("https://x.example/api/v1"),
            "https://x.example/api/v1/chat/completions"
        );
        assert_eq!(
            chat_completions_url("https://x/v1/chat/completions"),
            "https://x/v1/chat/completions"
        );
    }
}
