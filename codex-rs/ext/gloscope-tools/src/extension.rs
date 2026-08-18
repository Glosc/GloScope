//! `ToolContributor` wiring for the gloscope-tools extension.

use std::sync::Arc;

use codex_extension_api::ExtensionData;
use codex_extension_api::ExtensionRegistryBuilder;
use codex_extension_api::ToolCall;
use codex_extension_api::ToolContributor;
use codex_extension_api::ToolExecutor;

use crate::run_semgrep::SemgrepTool;
use crate::submit_verdict::SubmitVerdictTool;

#[derive(Clone, Default)]
pub(crate) struct GloscopeToolsExtension;

impl ToolContributor for GloscopeToolsExtension {
    fn tools(
        &self,
        _session_store: &ExtensionData,
        _thread_store: &ExtensionData,
    ) -> Vec<Arc<dyn ToolExecutor<ToolCall>>> {
        vec![Arc::new(SemgrepTool::new()), Arc::new(SubmitVerdictTool::new())]
    }
}

/// Installs the gloscope-tools extension's native tools into the extension
/// registry. Generic over `C` since this extension needs no config-scoped
/// state (unlike extensions that gate on feature flags).
pub fn install<C: Sync>(registry: &mut ExtensionRegistryBuilder<C>) {
    let extension = Arc::new(GloscopeToolsExtension);
    registry.tool_contributor(extension);
}
