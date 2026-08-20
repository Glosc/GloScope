//! Entry-point for the `gloscope-scan` binary: a headless driver that runs
//! the `run_semgrep` -> `triage` -> `submit_verdict` tool chain against a
//! target repo, without going through the GUI (`gloscope-app`) or legacy
//! Python CLI.

use clap::Parser;
use codex_arg0::Arg0DispatchPaths;
use codex_arg0::arg0_dispatch_or_else;
use codex_gloscope_scan::Cli;
use codex_gloscope_scan::run_main;

fn main() -> anyhow::Result<()> {
    arg0_dispatch_or_else(|arg0_paths: Arg0DispatchPaths| async move {
        let cli = Cli::parse();
        run_main(cli, arg0_paths).await
    })
}
