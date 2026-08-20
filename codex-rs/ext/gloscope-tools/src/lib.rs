//! Extension crate exposing GloScope's vulnerability-scanning tools
//! (`run_semgrep`, and future `submit_verdict`/`triage` tools) as native
//! codex `ToolContributor` implementations.

mod extension;
mod run_semgrep;
mod submit_verdict;
mod triage;

pub use extension::install;
pub use run_semgrep::RUN_SEMGREP_TOOL_NAME;
pub use submit_verdict::SUBMIT_VERDICT_TOOL_NAME;
pub use triage::TRIAGE_TOOL_NAME;
