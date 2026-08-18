//! Responses API tool definition for `submit_verdict`.

use codex_tools::JsonSchema;
use codex_tools::ResponsesApiTool;
use codex_tools::ToolSpec;
use std::collections::BTreeMap;

pub const SUBMIT_VERDICT_TOOL_NAME: &str = "submit_verdict";

const DESCRIPTION: &str = "Deeply verify a single vulnerability candidate (typically produced by \
`run_semgrep`) by running a self-contained, read-only-sandboxed `codex exec` sub-agent that \
traces the taint path from source to sink and reaches a verdict. Ported from \
`legacy-python/gloscope/verify.py`. Slow (a full nested agent turn per call, default budget \
600s) — call once per candidate, not in a tight loop without reason. Always returns a \
verification (never errors out on a real vulnerability question): a failed verification comes \
back as verdict=\"inconclusive\" with an `error` field explaining why, so a single flaky \
candidate cannot abort the whole scan.";

fn candidate_schema() -> JsonSchema {
    let properties = BTreeMap::from([
        (
            "checkId".to_string(),
            JsonSchema::string(Some("The semgrep rule id that produced this candidate.".to_string())),
        ),
        (
            "path".to_string(),
            JsonSchema::string(Some("Path to the file, relative to `target`.".to_string())),
        ),
        (
            "startLine".to_string(),
            JsonSchema::integer(Some("1-based start line of the flagged code.".to_string())),
        ),
        (
            "endLine".to_string(),
            JsonSchema::integer(Some("1-based end line of the flagged code.".to_string())),
        ),
        (
            "snippet".to_string(),
            JsonSchema::string(Some("The flagged source snippet.".to_string())),
        ),
        (
            "message".to_string(),
            JsonSchema::string(Some("The semgrep rule's message for this finding.".to_string())),
        ),
        (
            "cwe".to_string(),
            JsonSchema::string(Some(
                "CWE id, e.g. \"CWE-89\". Omit if unknown.".to_string(),
            )),
        ),
        (
            "category".to_string(),
            JsonSchema::string(Some(
                "Vulnerability category, e.g. \"sql_injection\". Defaults to \"unknown\"."
                    .to_string(),
            )),
        ),
        (
            "source".to_string(),
            JsonSchema::string(Some(
                "Which layer produced this candidate. Defaults to \"semgrep\".".to_string(),
            )),
        ),
    ]);
    JsonSchema::object(
        properties,
        Some(vec![
            "checkId".to_string(),
            "path".to_string(),
            "startLine".to_string(),
            "endLine".to_string(),
            "snippet".to_string(),
            "message".to_string(),
        ]),
        Some(false.into()),
    )
}

pub fn create_submit_verdict_tool() -> ToolSpec {
    let properties = BTreeMap::from([
        (
            "target".to_string(),
            JsonSchema::string(Some(
                "Required. Absolute path to the root of the target repository being scanned."
                    .to_string(),
            )),
        ),
        ("candidate".to_string(), candidate_schema()),
    ]);

    ToolSpec::Function(ResponsesApiTool {
        name: SUBMIT_VERDICT_TOOL_NAME.to_string(),
        description: DESCRIPTION.to_string(),
        strict: false,
        defer_loading: None,
        parameters: JsonSchema::object(
            properties,
            Some(vec!["target".to_string(), "candidate".to_string()]),
            Some(false.into()),
        ),
        output_schema: None,
    })
}
