//! Responses API tool definition for `run_semgrep`.

use codex_tools::JsonSchema;
use codex_tools::ResponsesApiTool;
use codex_tools::ToolSpec;
use std::collections::BTreeMap;

pub const RUN_SEMGREP_TOOL_NAME: &str = "run_semgrep";

const DESCRIPTION: &str = "Run semgrep against a target repository (or a subset of its Python \
files) to generate vulnerability candidates. Wraps `semgrep --json` with the bundled blind-spot \
rules (path-traversal patterns semgrep's `auto` ruleset misses) plus the registry's `auto` \
config, restricted to `*.py` files. Returns a list of candidates with a heuristically inferred \
CWE id and category; these are unverified leads, not confirmed vulnerabilities.";

pub fn create_run_semgrep_tool() -> ToolSpec {
    let properties = BTreeMap::from([
        (
            "target".to_string(),
            JsonSchema::string(Some(
                "Required. Absolute path to the root of the target repository to scan."
                    .to_string(),
            )),
        ),
        (
            "paths".to_string(),
            JsonSchema::array(
                JsonSchema::string(None),
                Some(
                    "Optional. Explicit list of files (relative to `target`) to scan instead of \
                     the whole repository. Mutually exclusive with `diff_base`."
                        .to_string(),
                ),
            ),
        ),
        (
            "diff_base".to_string(),
            JsonSchema::string(Some(
                "Optional. A git ref (branch, tag, or commit) to diff against; only files \
                 changed between this ref and HEAD are scanned. Mutually exclusive with `paths`."
                    .to_string(),
            )),
        ),
    ]);

    ToolSpec::Function(ResponsesApiTool {
        name: RUN_SEMGREP_TOOL_NAME.to_string(),
        description: DESCRIPTION.to_string(),
        strict: false,
        defer_loading: None,
        parameters: JsonSchema::object(
            properties,
            /* required */ Some(vec!["target".to_string()]),
            Some(false.into()),
        ),
        output_schema: None,
    })
}
