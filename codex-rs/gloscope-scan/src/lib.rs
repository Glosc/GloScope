//! Headless driver for the `run_semgrep` -> `triage` -> `submit_verdict`
//! tool chain (see `codex-gloscope-tools`), used by `evals/` to measure the
//! Rust/Tauri scanning stack's recall/false-positive rate without going
//! through the GUI (`gloscope-app`) or the legacy Python CLI.
//!
//! Mirrors `gloscope-app/src-tauri/src/lib.rs`'s config/app-server/thread
//! startup sequence (custom "gloscope" model provider, 16 MiB dedicated
//! stack thread) and `codex-rs/exec`'s headless event-draining loop
//! (auto-reject every `ServerRequest`, including `apply_patch` approval,
//! since this binary only verifies findings and never applies fixes).

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use codex_app_server_client::DEFAULT_IN_PROCESS_CHANNEL_CAPACITY;
use codex_app_server_client::EnvironmentManager;
use codex_app_server_client::ExecServerRuntimePaths;
use codex_app_server_client::InProcessAppServerClient;
use codex_app_server_client::InProcessClientStartArgs;
use codex_app_server_client::InProcessServerEvent;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::ConfigWarningNotification;
use codex_app_server_protocol::JSONRPCErrorError;
use codex_app_server_protocol::RequestId;
use codex_app_server_protocol::ServerNotification;
use codex_app_server_protocol::ServerRequest;
use codex_app_server_protocol::ThreadSource;
use codex_app_server_protocol::ThreadStartParams;
use codex_app_server_protocol::ThreadStartResponse;
use codex_app_server_protocol::TurnStartParams;
use codex_app_server_protocol::TurnStartResponse;
use codex_app_server_protocol::TurnStatus;
use codex_app_server_protocol::UserInput;
use codex_arg0::Arg0DispatchPaths;
use codex_config::CloudConfigBundleLoader;
use codex_config::LoaderOverrides;
use codex_core::config::Config;
use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_feedback::CodexFeedback;
use codex_gloscope_config::GloscopeConfig;
use codex_protocol::protocol::SessionSource;
use toml::Value as TomlValue;

/// Kept consistent with `gloscope-app`/`legacy-python/gloscope/verify.py`.
const PROVIDER_ID: &str = "gloscope";
const ENV_KEY: &str = "GLOSCOPE_API_KEY";
const CLIENT_NAME: &str = "gloscope-scan";

/// See `gloscope-app/src-tauri/src/lib.rs`'s `GLOSCOPE_CORE_STACK_SIZE_BYTES`:
/// codex-core's config/app-server startup recurses deeper than the default
/// ~2 MiB stack allows.
const GLOSCOPE_CORE_STACK_SIZE_BYTES: usize = 16 * 1024 * 1024;

const MODEL_CATALOG_JSON: &str = include_str!("../resources/model_catalog.json");

#[derive(Parser, Debug)]
#[command(name = "gloscope-scan")]
pub struct Cli {
    /// Path to the target repo to scan.
    #[arg(long)]
    pub target: PathBuf,

    /// Optional override for `GLOSCOPE_HOME` (defaults to `~/.gloscope`).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Directory to write run artifacts under (currently unused by this
    /// binary directly; `submit_verdict` writes findings under
    /// `<target>/.gloscope/scans/<run-id>/findings.jsonl` regardless).
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Optional comma-separated list of files (relative to `--target`) to
    /// restrict the scan to, mirroring `legacy-python/gloscope/cli.py`'s
    /// `--paths` (which restricts the semgrep subprocess's target file
    /// list — see `semgrep_runner.py`). Used by `evals/cve_replay.py` to
    /// scope a scan to just the file a CVE fix commit touched. Empty means
    /// scan the whole repo.
    #[arg(long, value_delimiter = ',')]
    pub paths: Vec<String>,
}

struct RequestIdSequencer {
    next: i64,
}

impl RequestIdSequencer {
    fn new() -> Self {
        Self { next: 1 }
    }

    fn next(&mut self) -> RequestId {
        let id = self.next;
        self.next += 1;
        RequestId::Integer(id)
    }
}

fn gloscope_codex_home() -> anyhow::Result<PathBuf> {
    let base =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("could not resolve home directory"))?;
    let home = base.join(".gloscope").join("scan-codex-home");
    std::fs::create_dir_all(&home)?;
    Ok(home)
}

fn write_model_catalog(codex_home: &Path) -> anyhow::Result<PathBuf> {
    let path = codex_home.join("gloscope_model_catalog.json");
    std::fs::write(&path, MODEL_CATALOG_JSON)?;
    Ok(path)
}

fn cli_overrides_for_provider(
    config: &GloscopeConfig,
    model_catalog_path: &Path,
    target: &Path,
) -> Vec<(String, TomlValue)> {
    vec![
        (
            format!("model_providers.{PROVIDER_ID}.name"),
            TomlValue::String("GloScope user provider".to_string()),
        ),
        (
            format!("model_providers.{PROVIDER_ID}.base_url"),
            TomlValue::String(config.base_url.clone()),
        ),
        (
            format!("model_providers.{PROVIDER_ID}.env_key"),
            TomlValue::String(ENV_KEY.to_string()),
        ),
        (
            format!("model_providers.{PROVIDER_ID}.wire_api"),
            TomlValue::String(config.wire_api.clone()),
        ),
        (
            "model_provider".to_string(),
            TomlValue::String(PROVIDER_ID.to_string()),
        ),
        (
            "model".to_string(),
            TomlValue::String(config.verify_model.clone()),
        ),
        (
            "model_catalog_json".to_string(),
            TomlValue::String(model_catalog_path.to_string_lossy().to_string()),
        ),
        (
            "cwd".to_string(),
            TomlValue::String(target.to_string_lossy().to_string()),
        ),
    ]
}

async fn build_config(
    gloscope_config: &GloscopeConfig,
    codex_home: PathBuf,
    target: &Path,
) -> anyhow::Result<(Config, Vec<(String, TomlValue)>)> {
    // SAFETY: single-threaded startup, before any other task reads this var.
    unsafe {
        std::env::set_var(ENV_KEY, &gloscope_config.api_key);
    }

    let model_catalog_path = write_model_catalog(&codex_home)?;
    let cli_overrides = cli_overrides_for_provider(gloscope_config, &model_catalog_path, target);
    let harness_overrides = ConfigOverrides {
        model_provider: Some(PROVIDER_ID.to_string()),
        cwd: Some(target.to_path_buf()),
        ..Default::default()
    };

    let config = ConfigBuilder::default()
        .codex_home(codex_home)
        .cli_overrides(cli_overrides.clone())
        .harness_overrides(harness_overrides)
        .loader_overrides(LoaderOverrides::default())
        .cloud_config_bundle(CloudConfigBundleLoader::default())
        .build()
        .await?;
    Ok((config, cli_overrides))
}

async fn start_app_server(
    config: Config,
    cli_overrides: Vec<(String, TomlValue)>,
) -> anyhow::Result<InProcessAppServerClient> {
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
        cli_overrides,
        loader_overrides: LoaderOverrides::default(),
        strict_config: false,
        cloud_config_bundle: CloudConfigBundleLoader::default(),
        feedback: CodexFeedback::new(),
        log_db: None,
        state_db: state_db.clone(),
        environment_manager: Arc::new(environment_manager),
        config_warnings,
        session_source: SessionSource::Custom(CLIENT_NAME.to_string()),
        enable_codex_api_key_env: true,
        client_name: CLIENT_NAME.to_string(),
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
    request_ids: &mut RequestIdSequencer,
) -> anyhow::Result<String> {
    let request_id = request_ids.next();
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

fn driving_prompt(target: &Path, paths: &[String]) -> String {
    let run_semgrep_step = if paths.is_empty() {
        format!("1. Call `run_semgrep` with target=\"{}\" to generate candidate findings.\n", target.display())
    } else {
        let paths_list = paths.join(", ");
        format!(
            "1. Call `run_semgrep` with target=\"{}\" and paths=[{}] to generate candidate \
             findings restricted to those files only.\n",
            target.display(),
            paths_list
        )
    };
    format!(
        "Scan the repository at `{}` for security vulnerabilities using the \
         available GloScope tools.\n\n\
         {run_semgrep_step}\
         2. For every candidate returned, call `triage` to get a keep/drop \
         decision.\n\
         3. For every candidate `triage` decides to keep, call `submit_verdict` \
         to verify it. Do not skip any kept candidate, and do not stop early \
         even if there are many candidates — process every single one.\n\
         4. Do not attempt to fix or patch any of the findings; your job is only \
         to detect and verify them.\n\
         5. Once every kept candidate has been verified, reply with exactly the \
         text `SCAN COMPLETE` and nothing else.",
        target.display(),
    )
}

async fn send_scan_turn(
    client: &InProcessAppServerClient,
    thread_id: &str,
    target: &Path,
    paths: &[String],
    request_ids: &mut RequestIdSequencer,
) -> anyhow::Result<String> {
    let request_id = request_ids.next();
    let params = TurnStartParams {
        thread_id: thread_id.to_string(),
        input: vec![UserInput::Text {
            text: driving_prompt(target, paths),
            text_elements: Vec::new(),
        }],
        ..Default::default()
    };
    let response: TurnStartResponse = client
        .request_typed(ClientRequest::TurnStart { request_id, params })
        .await
        .map_err(|err| anyhow::anyhow!("turn/start failed: {err}"))?;
    Ok(response.turn.id)
}

fn server_request_method_name(request: &ServerRequest) -> String {
    serde_json::to_value(request)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Rejects every server request. This binary only verifies findings — it
/// never needs to approve command execution or file changes — so unlike
/// `gloscope-app` (which surfaces `apply_patch` approvals to the user), a
/// blanket rejection is correct here, matching the plan's accepted risk that
/// gloscope-scan measures detection/verification only, not auto-fix.
async fn reject_all(client: &InProcessAppServerClient, request: ServerRequest) -> bool {
    let method = server_request_method_name(&request);
    let request_id = request.id().clone();
    let result = client
        .reject_server_request(
            request_id,
            JSONRPCErrorError {
                code: -32000,
                message: format!("`{method}` is not supported by gloscope-scan"),
                data: None,
            },
        )
        .await;
    if let Err(err) = result {
        tracing::warn!("failed to reject `{method}` server request: {err}");
        return true;
    }
    false
}

pub async fn run_main(cli: Cli, _arg0_paths: Arg0DispatchPaths) -> anyhow::Result<()> {
    if let Some(config_home) = &cli.config {
        // SAFETY: single-threaded startup, before any other task reads this var.
        unsafe {
            std::env::set_var("GLOSCOPE_HOME", config_home);
        }
    }

    let target = cli
        .target
        .canonicalize()
        .map_err(|err| anyhow::anyhow!("invalid --target `{}`: {err}", cli.target.display()))?;

    let gloscope_config = codex_gloscope_config::load_config()
        .map_err(|err| anyhow::anyhow!("failed to load GloScope config: {err}"))?;
    let paths = cli.paths;

    let handle = std::thread::Builder::new()
        .name("gloscope-scan-core".to_string())
        .stack_size(GLOSCOPE_CORE_STACK_SIZE_BYTES)
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "failed to build gloscope-scan-core tokio runtime: {err}"
                    ));
                }
            };
            rt.block_on(run_scan(gloscope_config, target, paths))
        })?;

    match handle.join() {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

async fn run_scan(
    gloscope_config: GloscopeConfig,
    target: PathBuf,
    paths: Vec<String>,
) -> anyhow::Result<()> {
    let codex_home = gloscope_codex_home()?;
    let (config, cli_overrides) = build_config(&gloscope_config, codex_home, &target).await?;
    let client = start_app_server(config.clone(), cli_overrides).await?;
    let mut request_ids = RequestIdSequencer::new();
    let thread_id = start_thread(&client, &config, &mut request_ids).await?;
    let turn_id = send_scan_turn(&client, &thread_id, &target, &paths, &mut request_ids).await?;

    let mut client = client;
    let mut error_seen = false;
    let mut last_error: Option<String> = None;
    loop {
        let Some(event) = client.next_event().await else {
            break;
        };
        match event {
            InProcessServerEvent::ServerRequest(request) => {
                if reject_all(&client, *request).await {
                    error_seen = true;
                }
            }
            InProcessServerEvent::ServerNotification(notification) => match *notification {
                ServerNotification::Error(payload)
                    if payload.thread_id == thread_id
                        && payload.turn_id == turn_id
                        && !payload.will_retry =>
                {
                    tracing::warn!("turn error: {:?}", payload.error);
                    last_error = Some(format!("{:?}", payload.error));
                    error_seen = true;
                }
                ServerNotification::TurnCompleted(payload)
                    if payload.thread_id == thread_id && payload.turn.id == turn_id =>
                {
                    if matches!(
                        payload.turn.status,
                        TurnStatus::Failed | TurnStatus::Interrupted
                    ) {
                        error_seen = true;
                    }
                    break;
                }
                _ => {}
            },
            InProcessServerEvent::Lagged { skipped } => {
                tracing::warn!("dropped {skipped} lagged app-server event(s)");
            }
        }
    }

    if let Err(err) = client.shutdown().await {
        tracing::warn!("in-process app-server shutdown failed: {err}");
    }

    if error_seen {
        match last_error {
            Some(detail) => anyhow::bail!("scan turn did not complete successfully: {detail}"),
            None => anyhow::bail!(
                "scan turn did not complete successfully (no error notification observed; \
                 turn status was Failed/Interrupted, or a server request was rejected)"
            ),
        }
    }
    Ok(())
}
