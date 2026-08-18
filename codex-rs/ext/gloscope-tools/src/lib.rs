//! Extension crate exposing GloScope's vulnerability-scanning tools
//! (`run_semgrep`, and future `submit_verdict`/`triage` tools) as native
//! codex `ToolContributor` implementations.

mod config;
mod extension;
mod run_semgrep;
mod submit_verdict;

pub use extension::install;
pub use run_semgrep::RUN_SEMGREP_TOOL_NAME;
pub use submit_verdict::SUBMIT_VERDICT_TOOL_NAME;
