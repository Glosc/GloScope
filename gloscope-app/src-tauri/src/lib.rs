use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;

use codex_app_server_client::DEFAULT_IN_PROCESS_CHANNEL_CAPACITY;
use codex_app_server_client::EnvironmentManager;
use codex_app_server_client::ExecServerRuntimePaths;
use codex_app_server_client::InProcessAppServerClient;
use codex_app_server_client::InProcessAppServerRequestHandle;
use codex_app_server_client::InProcessClientStartArgs;
use codex_app_server_client::InProcessServerEvent;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::ConfigWarningNotification;
use codex_app_server_protocol::FileChangeApprovalDecision;
use codex_app_server_protocol::FileChangeRequestApprovalResponse;
use codex_app_server_protocol::JSONRPCErrorError;
use codex_app_server_protocol::RequestId;
use codex_app_server_protocol::ServerRequest;
use codex_app_server_protocol::ThreadSource;
use codex_app_server_protocol::ThreadStartParams;
use codex_app_server_protocol::ThreadStartResponse;
use codex_app_server_protocol::TurnStartParams;
use codex_app_server_protocol::UserInput;
use codex_arg0::Arg0DispatchPaths;
use codex_config::CloudConfigBundleLoader;
use codex_config::LoaderOverrides;
use codex_core::config::Config;
use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_feedback::CodexFeedback;
use codex_protocol::protocol::SessionSource;
use tauri::Emitter;
use tauri::Manager;
use toml::Value as TomlValue;

/// Provider id / env var, kept consistent with the legacy Python pipeline
/// (`legacy-python/gloscope/verify.py`: `PROVIDER_ID`, `ENV_KEY`).
const PROVIDER_ID: &str = "gloscope";
const ENV_KEY: &str = "GLOSCOPE_API_KEY";

struct GloscopeSettings {
    base_url: String,
    api_key: String,
    verify_model: String,
}

/// State shared with Tauri commands. The `InProcessAppServerClient` itself is
/// moved into the background event-draining task; commands only need a
/// cloneable request handle plus the thread id created at startup.
struct AppState {
    request_handle: InProcessAppServerRequestHandle,
    next_request_id: AtomicI64,
    thread_id: String,
    /// `item/fileChange/requestApproval` requests awaiting a decision from the
    /// frontend, keyed by the request's string-rendered `RequestId`. Only
    /// this one `ServerRequest` variant is tracked for now (see
    /// `run_event_loop`) — everything else is still auto-rejected as before.
    pending_patch_approvals: Mutex<HashMap<String, RequestId>>,
}

impl AppState {
    fn next_id(&self) -> RequestId {
        RequestId::Integer(self.next_request_id.fetch_add(1, Ordering::SeqCst))
    }
}

/// Reads `[provider]`/`[models]` from `gloscope.toml`/`config.local.toml`,
/// searching the current directory and its ancestors (mirrors
/// `legacy-python/gloscope/config.py::_find_config_file`, generalized to walk
/// up from wherever the Tauri process happens to be launched).
fn load_gloscope_settings() -> anyhow::Result<GloscopeSettings> {
    const CONFIG_FILENAMES: [&str; 2] = ["gloscope.toml", "config.local.toml"];

    let mut dir = std::env::current_dir()?;
    let config_path = loop {
        let found = CONFIG_FILENAMES
            .iter()
            .map(|name| dir.join(name))
            .find(|path| path.is_file());
        if let Some(path) = found {
            break path;
        }
        if !dir.pop() {
            anyhow::bail!(
                "no gloscope.toml / config.local.toml found in {:?} or any ancestor directory",
                std::env::current_dir()?
            );
        }
    };

    let raw = std::fs::read_to_string(&config_path)?;
    let parsed: TomlValue = toml::from_str(&raw)?;

    let provider = parsed.get("provider");
    let models = parsed.get("models");

    let base_url = provider
        .and_then(|p| p.get("base_url"))
        .and_then(TomlValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("config missing [provider] base_url"))?
        .to_string();
    let api_key = provider
        .and_then(|p| p.get("api_key"))
        .and_then(TomlValue::as_str)
        .map(str::to_string)
        .or_else(|| std::env::var(ENV_KEY).ok())
        .ok_or_else(|| {
            anyhow::anyhow!("config missing [provider] api_key (or {ENV_KEY} env var)")
        })?;
    let triage_model = models
        .and_then(|m| m.get("triage_model"))
        .and_then(TomlValue::as_str)
        .map(str::to_string);
    let verify_model = models
        .and_then(|m| m.get("verify_model"))
        .and_then(TomlValue::as_str)
        .map(str::to_string)
        .or(triage_model)
        .ok_or_else(|| anyhow::anyhow!("config missing [models] triage_model/verify_model"))?;

    Ok(GloscopeSettings {
        base_url,
        api_key,
        verify_model,
    })
}

fn gloscope_codex_home() -> anyhow::Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("could not resolve home directory"))?;
    let home = base.join(".gloscope").join("codex-home");
    std::fs::create_dir_all(&home)?;
    Ok(home)
}

/// Bundled model catalog for GloScope's custom (non-OpenAI-catalog) model
/// slugs, e.g. `deepseek-v4-pro`/`deepseek-v4-flash`. Without this, those
/// slugs miss the bundled catalog (`models-manager/models.json`) and fall
/// back to `model_info_from_slug()`, which hardcodes
/// `apply_patch_tool_type: None` — silently disabling the `apply_patch` tool
/// for every GloScope session. Written out to `codex_home` at startup so it
/// can be referenced by an absolute `model_catalog_json` path.
const MODEL_CATALOG_JSON: &str = include_str!("../resources/model_catalog.json");

fn write_model_catalog(codex_home: &std::path::Path) -> anyhow::Result<PathBuf> {
    let path = codex_home.join("gloscope_model_catalog.json");
    std::fs::write(&path, MODEL_CATALOG_JSON)?;
    Ok(path)
}

fn cli_overrides_for_provider(
    settings: &GloscopeSettings,
    model_catalog_path: &std::path::Path,
) -> Vec<(String, TomlValue)> {
    vec![
        (
            format!("model_providers.{PROVIDER_ID}.name"),
            TomlValue::String("GloScope user provider".to_string()),
        ),
        (
            format!("model_providers.{PROVIDER_ID}.base_url"),
            TomlValue::String(settings.base_url.clone()),
        ),
        (
            format!("model_providers.{PROVIDER_ID}.env_key"),
            TomlValue::String(ENV_KEY.to_string()),
        ),
        (
            format!("model_providers.{PROVIDER_ID}.wire_api"),
            TomlValue::String("responses".to_string()),
        ),
        (
            "model_provider".to_string(),
            TomlValue::String(PROVIDER_ID.to_string()),
        ),
        ("model".to_string(), TomlValue::String(settings.verify_model.clone())),
        (
            "model_catalog_json".to_string(),
            TomlValue::String(model_catalog_path.to_string_lossy().to_string()),
        ),
    ]
}

async fn build_config(settings: &GloscopeSettings, codex_home: PathBuf) -> anyhow::Result<Config> {
    // SAFETY: single-threaded startup, before any other task reads this var.
    unsafe {
        std::env::set_var(ENV_KEY, &settings.api_key);
    }

    let model_catalog_path = write_model_catalog(&codex_home)?;
    let cli_overrides = cli_overrides_for_provider(settings, &model_catalog_path);
    let harness_overrides = ConfigOverrides {
        model_provider: Some(PROVIDER_ID.to_string()),
        ..Default::default()
    };

    let config = ConfigBuilder::default()
        .codex_home(codex_home)
        .cli_overrides(cli_overrides)
        .harness_overrides(harness_overrides)
        .loader_overrides(LoaderOverrides::default())
        .cloud_config_bundle(CloudConfigBundleLoader::default())
        .build()
        .await?;
    Ok(config)
}

async fn start_app_server(config: Config) -> anyhow::Result<InProcessAppServerClient> {
    let config_warnings: Vec<ConfigWarningNotification> = config
        .startup_warnings
        .iter()
        .map(|warning| ConfigWarningNotification {
            summary: warning.clone(),
            details: None,
            path: None,
            range: None,
        })
        .collect();

    let codex_self_exe = std::env::current_exe().ok();
    let local_runtime_paths =
        ExecServerRuntimePaths::from_optional_paths(codex_self_exe.clone(), None)?;
    let state_db = codex_core::init_state_db(&config).await;
    let environment_manager = EnvironmentManager::from_codex_home(
        config.codex_home.clone(),
        Some(local_runtime_paths),
        config.http_client_factory(),
    )
    .await?;

    let args = InProcessClientStartArgs {
        arg0_paths: Arg0DispatchPaths {
            codex_self_exe,
            ..Default::default()
        },
        config: Arc::new(config.clone()),
        cli_overrides: Vec::new(),
        loader_overrides: LoaderOverrides::default(),
        strict_config: false,
        cloud_config_bundle: CloudConfigBundleLoader::default(),
        feedback: CodexFeedback::new(),
        log_db: None,
        state_db: state_db.clone(),
        environment_manager: Arc::new(environment_manager),
        config_warnings,
        session_source: SessionSource::Custom("gloscope-app".to_string()),
        enable_codex_api_key_env: true,
        client_name: "gloscope-app".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        experimental_api: true,
        mcp_server_openai_form_elicitation: false,
        opt_out_notification_methods: Vec::new(),
        channel_capacity: DEFAULT_IN_PROCESS_CHANNEL_CAPACITY,
    };

    let client = InProcessAppServerClient::start(args).await?;
    Ok(client)
}

async fn start_thread(
    client: &InProcessAppServerClient,
    config: &Config,
    request_id_seq: &AtomicI64,
) -> anyhow::Result<String> {
    let request_id = RequestId::Integer(request_id_seq.fetch_add(1, Ordering::SeqCst));
    let params = ThreadStartParams {
        model: config.model.clone(),
        model_provider: Some(config.model_provider_id.clone()),
        cwd: Some(config.cwd.to_string_lossy().to_string()),
        thread_source: Some(ThreadSource::User),
        ..Default::default()
    };
    let response: ThreadStartResponse = client
        .request_typed(ClientRequest::ThreadStart { request_id, params })
        .await
        .map_err(|err| anyhow::anyhow!("thread/start failed: {err}"))?;
    Ok(response.thread.id)
}

/// Drains in-process app-server events and forwards the ones the frontend
/// cares about as Tauri events. `item/fileChange/requestApproval` (the
/// apply_patch approval prompt) is surfaced to the frontend and left pending
/// in `AppState::pending_patch_approvals` until `respond_to_patch_approval`
/// answers it. Every other `ServerRequest` variant is still rejected,
/// matching `codex-rs/exec`'s non-interactive behavior for M2.
async fn run_event_loop(mut client: InProcessAppServerClient, app_handle: tauri::AppHandle) {
    while let Some(event) = client.next_event().await {
        match event {
            InProcessServerEvent::ServerNotification(notification) => {
                if let Ok(value) = serde_json::to_value(notification.as_ref()) {
                    let _ = app_handle.emit("gloscope://notification", value);
                }
            }
            InProcessServerEvent::ServerRequest(request) => {
                let request = *request;
                match request {
                    ServerRequest::FileChangeRequestApproval { request_id, params } => {
                        let key = request_id.to_string();
                        if let Some(state) = app_handle.try_state::<AppState>() {
                            state
                                .pending_patch_approvals
                                .lock()
                                .expect("pending_patch_approvals mutex poisoned")
                                .insert(key.clone(), request_id.clone());
                        }
                        if let Ok(value) = serde_json::to_value(&params) {
                            let mut payload = value;
                            if let Some(obj) = payload.as_object_mut() {
                                obj.insert(
                                    "requestId".to_string(),
                                    serde_json::Value::String(key),
                                );
                            }
                            let _ = app_handle.emit("gloscope://patchApprovalRequest", payload);
                        }
                    }
                    other => {
                        let request_id = other.id().clone();
                        let method = serde_json::to_value(&other)
                            .ok()
                            .and_then(|v| {
                                v.get("method").and_then(|m| m.as_str()).map(str::to_string)
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                        let _ = client
                            .reject_server_request(
                                request_id,
                                JSONRPCErrorError {
                                    code: -32000,
                                    message: format!(
                                        "`{method}` is not supported by gloscope-app yet"
                                    ),
                                    data: None,
                                },
                            )
                            .await;
                    }
                }
            }
            InProcessServerEvent::Lagged { skipped } => {
                eprintln!("gloscope-app: dropped {skipped} lagged app-server event(s)");
            }
        }
    }
}

#[tauri::command]
async fn send_message(
    message: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let request_id = state.next_id();
    let params = TurnStartParams {
        thread_id: state.thread_id.clone(),
        input: vec![UserInput::Text {
            text: message,
            text_elements: Vec::new(),
        }],
        ..Default::default()
    };
    state
        .request_handle
        .request(ClientRequest::TurnStart { request_id, params })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.message)?;
    Ok(())
}

/// Answers a pending `item/fileChange/requestApproval` request (an
/// `apply_patch` approval prompt) surfaced to the frontend via the
/// `gloscope://patchApprovalRequest` event. `accept` maps to
/// `FileChangeApprovalDecision::Accept`, anything else to `Decline` — this is
/// intentionally the two-button minimum (M6b scope), not the full decision
/// set `codex-rs/tui` exposes (accept-for-session, cancel-and-interrupt).
#[tauri::command]
async fn respond_to_patch_approval(
    request_id: String,
    accept: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let pending = state
        .pending_patch_approvals
        .lock()
        .expect("pending_patch_approvals mutex poisoned")
        .remove(&request_id);
    let Some(pending) = pending else {
        return Err(format!("no pending patch approval for request {request_id}"));
    };

    let decision = if accept {
        FileChangeApprovalDecision::Accept
    } else {
        FileChangeApprovalDecision::Decline
    };
    let response = FileChangeRequestApprovalResponse { decision };
    let result = serde_json::to_value(response).map_err(|err| err.to_string())?;
    state
        .request_handle
        .resolve_server_request(pending, result)
        .await
        .map_err(|err| err.to_string())
}

/// codex-core's config/app-server startup recurses deeply enough that it
/// needs a larger-than-default worker stack (see `codex-rs/arg0`'s
/// `TOKIO_WORKER_STACK_SIZE_BYTES`, also 16 MiB). Tauri's own async runtime
/// uses tokio's default ~2 MiB stack, which overflows here, so this work runs
/// on a dedicated OS thread with its own single-threaded tokio runtime.
const GLOSCOPE_CORE_STACK_SIZE_BYTES: usize = 16 * 1024 * 1024;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            send_message,
            respond_to_patch_approval
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            std::thread::Builder::new()
                .name("gloscope-core".to_string())
                .stack_size(GLOSCOPE_CORE_STACK_SIZE_BYTES)
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("failed to build gloscope-core tokio runtime");
                    rt.block_on(async move {
                        let settings = match load_gloscope_settings() {
                    Ok(settings) => settings,
                    Err(err) => {
                        eprintln!("gloscope-app: failed to load config: {err}");
                        return;
                    }
                };
                let codex_home = match gloscope_codex_home() {
                    Ok(path) => path,
                    Err(err) => {
                        eprintln!("gloscope-app: failed to resolve codex home: {err}");
                        return;
                    }
                };
                let config = match build_config(&settings, codex_home).await {
                    Ok(config) => config,
                    Err(err) => {
                        eprintln!("gloscope-app: failed to build config: {err}");
                        return;
                    }
                };
                let client = match start_app_server(config.clone()).await {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("gloscope-app: failed to start app-server: {err}");
                        return;
                    }
                };
                let request_id_seq = AtomicI64::new(1);
                let thread_id = match start_thread(&client, &config, &request_id_seq).await {
                    Ok(id) => id,
                    Err(err) => {
                        eprintln!("gloscope-app: failed to start thread: {err}");
                        return;
                    }
                };

                        let request_handle = client.request_handle();
                        app_handle.manage(AppState {
                            request_handle,
                            next_request_id: request_id_seq,
                            thread_id,
                            pending_patch_approvals: Mutex::new(HashMap::new()),
                        });

                        run_event_loop(client, app_handle).await;
                    });
                })
                .expect("failed to spawn gloscope-core thread");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

