//! `ToolContributor` wiring for the gloscope-tools extension.

use std::sync::Arc;

use codex_extension_api::ExtensionData;
use codex_extension_api::ExtensionRegistryBuilder;
use codex_extension_api::ToolCall;
use codex_extension_api::ToolContributor;
use codex_extension_api::ToolExecutor;

use crate::run_semgrep::SemgrepTool;
use crate::submit_verdict::SubmitVerdictTool;
use crate::submit_verdict::generate_run_id;
use crate::triage::TriageTool;

/// Thread-scoped `submit_verdict` run id, resolved once per thread via
/// `thread_store.get_or_init` (see `tools()` below) rather than once per
/// `tools()` call — `tools()` runs once per sampling *step*, not once per
/// thread, so constructing a fresh id inside `SubmitVerdictTool::new()` on
/// every call fragmented one scan's findings across many single-finding
/// `.gloscope/scans/<run_id>/` directories instead of one accumulating run.
struct GloscopeRunId(String);

#[derive(Clone, Default)]
pub(crate) struct GloscopeToolsExtension;

impl ToolContributor for GloscopeToolsExtension {
    fn tools(
        &self,
        _session_store: &ExtensionData,
        thread_store: &ExtensionData,
    ) -> Vec<Arc<dyn ToolExecutor<ToolCall>>> {
        let run_id = thread_store
            .get_or_init(|| GloscopeRunId(generate_run_id()))
            .0
            .clone();
        vec![
            Arc::new(SemgrepTool::new()),
            Arc::new(SubmitVerdictTool::with_run_id(run_id)),
            Arc::new(TriageTool::new()),
        ]
    }
}

/// Installs the gloscope-tools extension's native tools into the extension
/// registry. Generic over `C` since this extension needs no config-scoped
/// state (unlike extensions that gate on feature flags).
pub fn install<C: Sync>(registry: &mut ExtensionRegistryBuilder<C>) {
    let extension = Arc::new(GloscopeToolsExtension);
    registry.tool_contributor(extension);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_reuses_run_id_across_calls_on_same_thread_store() {
        let session_store = ExtensionData::new("session-1");
        let thread_store = ExtensionData::new("thread-1");
        let extension = GloscopeToolsExtension;

        extension.tools(&session_store, &thread_store);
        let first_run_id = thread_store
            .get::<GloscopeRunId>()
            .expect("run id should be stored on first tools() call")
            .0
            .clone();

        // Simulate `tools()` being invoked again for a later sampling step
        // within the same thread (the scenario that used to fragment one
        // scan's findings across many run directories).
        extension.tools(&session_store, &thread_store);
        let second_run_id = thread_store
            .get::<GloscopeRunId>()
            .expect("run id should still be stored")
            .0
            .clone();

        assert_eq!(
            first_run_id, second_run_id,
            "run id must be stable across tools() calls within one thread"
        );
    }

    #[test]
    fn tools_uses_different_run_id_across_different_thread_stores() {
        let session_store = ExtensionData::new("session-1");
        let thread_store_a = ExtensionData::new("thread-a");
        let thread_store_b = ExtensionData::new("thread-b");
        let extension = GloscopeToolsExtension;

        extension.tools(&session_store, &thread_store_a);
        // `generate_run_id()` is a millisecond timestamp; without a small
        // delay two calls in the same test can land in the same millisecond
        // and produce equal ids even though they come from distinct stores.
        std::thread::sleep(std::time::Duration::from_millis(2));
        extension.tools(&session_store, &thread_store_b);

        let run_id_a = thread_store_a.get::<GloscopeRunId>().unwrap().0.clone();
        let run_id_b = thread_store_b.get::<GloscopeRunId>().unwrap().0.clone();

        assert_ne!(
            run_id_a, run_id_b,
            "distinct threads must not share a run id"
        );
    }
}
