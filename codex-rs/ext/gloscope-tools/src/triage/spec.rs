//! Responses API tool definition for `triage`.

use crate::submit_verdict::spec::candidate_schema;
use codex_tools::JsonSchema;
use codex_tools::ResponsesApiTool;
use codex_tools::ToolSpec;
use std::collections::BTreeMap;

pub const TRIAGE_TOOL_NAME: &str = "triage";

const DESCRIPTION: &str = "Cheaply triage a single vulnerability candidate (typically produced by \
`run_semgrep`) with a single chat-completion call to the configured cheap model: keep (worth a \
deep `submit_verdict` pass) or drop (an obvious false positive). Ported from \
`legacy-python/gloscope/triage.py`. Fast — a single HTTP round trip, not a nested agent turn. \
Fail-open: any HTTP/parse failure returns keep=true with an explanatory reason rather than \
erroring out, so a single flaky candidate cannot cause a real vulnerability to be silently \
dropped.";

pub fn create_triage_tool() -> ToolSpec {
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
        name: TRIAGE_TOOL_NAME.to_string(),
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
