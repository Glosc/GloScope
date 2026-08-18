//! Extension crate exposing GloScope's vulnerability-scanning tools
//! (`run_semgrep`, and future `submit_verdict`/`triage` tools) as native
//! codex `ToolContributor` implementations.

mod extension;
mod run_semgrep;

pub use extension::install;
pub use run_semgrep::RUN_SEMGREP_TOOL_NAME;
