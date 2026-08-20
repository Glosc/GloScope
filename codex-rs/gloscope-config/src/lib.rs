//! Centralized GloScope provider/model configuration, shared by
//! `gloscope-app` (the Tauri host session) and `codex-gloscope-tools`
//! (`run_semgrep`/`submit_verdict`/`triage`, invoked while scanning an
//! arbitrary target repo).
//!
//! Before this crate existed, the two call sites each searched for a
//! `gloscope.toml`/`config.local.toml` independently — `gloscope-app` walked
//! up from its CWD, `gloscope-tools` looked inside whatever target directory
//! was being scanned. That meant a working setup in one context could still
//! be "unconfigured" in the other, and the API key sat in a plaintext file
//! either way. This crate centralizes both concerns: non-secret settings
//! live in one TOML file under a fixed home directory, and the API key lives
//! in the OS keyring (via `codex-secrets`), read once regardless of which
//! repo is being scanned.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use codex_keyring_store::DefaultKeyringStore;
use codex_keyring_store::KeyringStore;
use codex_secrets::SecretName;
use codex_secrets::SecretScope;
use codex_secrets::SecretsBackendKind;
use codex_secrets::SecretsManager;
use serde::Deserialize;
use serde::Serialize;

const SETTINGS_FILENAME: &str = "settings.toml";
const API_KEY_SECRET_NAME: &str = "GLOSCOPE_API_KEY";
/// Fallback for scripted/CI usage (e.g. `evals/cve_replay.py`) where reading
/// the OS keyring isn't practical. Checked only when no key is stored yet.
const API_KEY_ENV_FALLBACK: &str = "GLOSCOPE_API_KEY";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "GloScope 尚未完成首次配置：请在设置向导中填写 provider/模型信息（settings.toml 不存在于 {}）",
        .0.display()
    )]
    NotConfigured(PathBuf),
    #[error("读取配置文件失败: {0}")]
    Read(String),
    #[error("写入配置文件失败: {0}")]
    Write(String),
    #[error("配置文件不是合法 TOML: {0}")]
    InvalidToml(String),
    #[error("序列化配置失败: {0}")]
    SerializeToml(String),
    #[error("配置缺少 base_url")]
    MissingBaseUrl,
    #[error("配置缺少 triage_model")]
    MissingTriageModel,
    #[error(
        "未配置 API key：请在设置向导中填写，或设置环境变量 {API_KEY_ENV_FALLBACK}"
    )]
    MissingApiKey,
    #[error("读取/写入 API key 失败: {0}")]
    Secret(String),
}

/// Non-secret provider/model settings, persisted as plain TOML at
/// `<home>/settings.toml`. The API key is deliberately not a field here — it
/// never touches disk in plaintext, see [`load_api_key`]/[`save_api_key`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GloscopeSettings {
    pub base_url: String,
    pub triage_model: String,
    pub verify_model: String,
    #[serde(default = "default_wire_api")]
    pub wire_api: String,
    #[serde(default = "default_triage_timeout")]
    pub triage_timeout_secs: f64,
    #[serde(default = "default_verify_timeout")]
    pub verify_timeout_secs: f64,
}

fn default_wire_api() -> String {
    "responses".to_string()
}

fn default_triage_timeout() -> f64 {
    60.0
}

fn default_verify_timeout() -> f64 {
    600.0
}

/// Fully resolved configuration (settings + API key) consumed by the tools
/// that actually make provider calls (`submit_verdict`, `triage`, and
/// `gloscope-app`'s own host-session wiring).
#[derive(Debug, Clone, PartialEq)]
pub struct GloscopeConfig {
    pub base_url: String,
    pub api_key: String,
    pub triage_model: String,
    pub verify_model: String,
    pub wire_api: String,
    pub triage_timeout: Duration,
    pub verify_timeout: Duration,
}

/// `~/.gloscope` — the fixed home directory for GloScope's own settings,
/// independent of any target repo being scanned and independent of the
/// host codex session's own `CODEX_HOME`.
pub fn gloscope_home() -> PathBuf {
    if let Ok(path) = std::env::var("GLOSCOPE_HOME") {
        return PathBuf::from(path);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gloscope")
}

fn settings_path(home: &Path) -> PathBuf {
    home.join(SETTINGS_FILENAME)
}

/// `true` once a settings file has been written by the setup wizard. Used by
/// the frontend to decide whether to show the wizard or the chat view.
pub fn is_configured(home: &Path) -> bool {
    settings_path(home).is_file()
}

pub fn load_settings(home: &Path) -> Result<GloscopeSettings, ConfigError> {
    let path = settings_path(home);
    if !path.is_file() {
        return Err(ConfigError::NotConfigured(home.to_path_buf()));
    }
    let text = std::fs::read_to_string(&path).map_err(|err| ConfigError::Read(err.to_string()))?;
    toml::from_str(&text).map_err(|err| ConfigError::InvalidToml(err.to_string()))
}

pub fn save_settings(home: &Path, settings: &GloscopeSettings) -> Result<(), ConfigError> {
    if settings.base_url.trim().is_empty() {
        return Err(ConfigError::MissingBaseUrl);
    }
    if settings.triage_model.trim().is_empty() {
        return Err(ConfigError::MissingTriageModel);
    }
    std::fs::create_dir_all(home).map_err(|err| ConfigError::Write(err.to_string()))?;
    let text =
        toml::to_string_pretty(settings).map_err(|err| ConfigError::SerializeToml(err.to_string()))?;
    std::fs::write(settings_path(home), text).map_err(|err| ConfigError::Write(err.to_string()))
}

fn secrets_manager(home: &Path, keyring_store: Arc<dyn KeyringStore>) -> SecretsManager {
    SecretsManager::new_with_keyring_store(
        home.to_path_buf(),
        SecretsBackendKind::Local,
        keyring_store,
    )
}

fn api_key_secret_name() -> SecretName {
    // Fixed, valid `SecretName` (uppercase ASCII + digits/underscore only) —
    // `expect` here would only ever fail on a typo in the literal above.
    #[allow(clippy::expect_used)]
    SecretName::new(API_KEY_SECRET_NAME).expect("API_KEY_SECRET_NAME must be a valid SecretName")
}

pub fn save_api_key(
    home: &Path,
    keyring_store: Arc<dyn KeyringStore>,
    api_key: &str,
) -> Result<(), ConfigError> {
    secrets_manager(home, keyring_store)
        .set(&SecretScope::Global, &api_key_secret_name(), api_key)
        .map_err(|err| ConfigError::Secret(err.to_string()))
}

pub fn load_api_key(
    home: &Path,
    keyring_store: Arc<dyn KeyringStore>,
) -> Result<Option<String>, ConfigError> {
    secrets_manager(home, keyring_store)
        .get(&SecretScope::Global, &api_key_secret_name())
        .map_err(|err| ConfigError::Secret(err.to_string()))
}

/// Loads the fully resolved config using the real OS keyring and
/// [`gloscope_home`]. Falls back to the `GLOSCOPE_API_KEY` env var when no
/// key has been stored yet (scripted/CI usage).
pub fn load_config() -> Result<GloscopeConfig, ConfigError> {
    load_config_with(&gloscope_home(), Arc::new(DefaultKeyringStore))
}

/// Same as [`load_config`] but with an injectable home dir + keyring store,
/// for tests and for callers that need an isolated `GLOSCOPE_HOME` override.
pub fn load_config_with(
    home: &Path,
    keyring_store: Arc<dyn KeyringStore>,
) -> Result<GloscopeConfig, ConfigError> {
    let settings = load_settings(home)?;
    let api_key = load_api_key(home, keyring_store)?
        .or_else(|| std::env::var(API_KEY_ENV_FALLBACK).ok())
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::MissingApiKey)?;

    Ok(GloscopeConfig {
        base_url: settings.base_url,
        api_key,
        triage_model: settings.triage_model.clone(),
        verify_model: if settings.verify_model.trim().is_empty() {
            settings.triage_model
        } else {
            settings.verify_model
        },
        wire_api: settings.wire_api,
        triage_timeout: Duration::from_secs_f64(settings.triage_timeout_secs),
        verify_timeout: Duration::from_secs_f64(settings.verify_timeout_secs),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use codex_keyring_store::tests::MockKeyringStore;
    use tempfile::TempDir;

    const FAKE_KEY: &str = "fake-key-for-unit-tests";

    fn settings_fixture() -> GloscopeSettings {
        GloscopeSettings {
            base_url: "https://api.deepseek.com".to_string(),
            triage_model: "deepseek-v4-flash".to_string(),
            verify_model: "deepseek-v4-pro".to_string(),
            wire_api: "responses".to_string(),
            triage_timeout_secs: 60.0,
            verify_timeout_secs: 600.0,
        }
    }

    #[test]
    fn not_configured_before_save() {
        let tmp = TempDir::new().expect("tempdir");
        assert!(!is_configured(tmp.path()));
        let err = load_settings(tmp.path()).expect_err("should error");
        assert!(matches!(err, ConfigError::NotConfigured(_)));
    }

    #[test]
    fn save_then_load_settings_round_trips() {
        let tmp = TempDir::new().expect("tempdir");
        save_settings(tmp.path(), &settings_fixture()).expect("save");
        assert!(is_configured(tmp.path()));
        let loaded = load_settings(tmp.path()).expect("load");
        assert_eq!(loaded, settings_fixture());
    }

    #[test]
    fn save_rejects_missing_base_url() {
        let tmp = TempDir::new().expect("tempdir");
        let mut settings = settings_fixture();
        settings.base_url = String::new();
        let err = save_settings(tmp.path(), &settings).expect_err("should error");
        assert!(matches!(err, ConfigError::MissingBaseUrl));
    }

    #[test]
    fn api_key_round_trips_through_keyring() {
        let tmp = TempDir::new().expect("tempdir");
        let keyring: Arc<dyn KeyringStore> = Arc::new(MockKeyringStore::default());
        assert_eq!(load_api_key(tmp.path(), keyring.clone()).expect("load"), None);
        save_api_key(tmp.path(), keyring.clone(), FAKE_KEY).expect("save");
        assert_eq!(
            load_api_key(tmp.path(), keyring).expect("load"),
            Some(FAKE_KEY.to_string())
        );
    }

    #[test]
    fn load_config_combines_settings_and_keyring_key() {
        let tmp = TempDir::new().expect("tempdir");
        let keyring: Arc<dyn KeyringStore> = Arc::new(MockKeyringStore::default());
        save_settings(tmp.path(), &settings_fixture()).expect("save settings");
        save_api_key(tmp.path(), keyring.clone(), FAKE_KEY).expect("save key");

        let cfg = load_config_with(tmp.path(), keyring).expect("load");
        assert_eq!(cfg.base_url, "https://api.deepseek.com");
        assert_eq!(cfg.api_key, FAKE_KEY);
        assert_eq!(cfg.triage_model, "deepseek-v4-flash");
        assert_eq!(cfg.verify_model, "deepseek-v4-pro");
        assert_eq!(cfg.verify_timeout, Duration::from_secs_f64(600.0));
    }

    #[test]
    fn load_config_falls_back_to_env_var_when_no_key_stored() {
        let tmp = TempDir::new().expect("tempdir");
        let keyring: Arc<dyn KeyringStore> = Arc::new(MockKeyringStore::default());
        save_settings(tmp.path(), &settings_fixture()).expect("save settings");

        // SAFETY: single-threaded test process; no concurrent env access.
        unsafe {
            std::env::set_var(API_KEY_ENV_FALLBACK, FAKE_KEY);
        }
        let result = load_config_with(tmp.path(), keyring);
        unsafe {
            std::env::remove_var(API_KEY_ENV_FALLBACK);
        }
        assert_eq!(result.expect("loads").api_key, FAKE_KEY);
    }

    #[test]
    fn load_config_missing_api_key_is_clear_error() {
        let tmp = TempDir::new().expect("tempdir");
        let keyring: Arc<dyn KeyringStore> = Arc::new(MockKeyringStore::default());
        save_settings(tmp.path(), &settings_fixture()).expect("save settings");
        let err = load_config_with(tmp.path(), keyring).expect_err("should error");
        assert!(matches!(err, ConfigError::MissingApiKey));
    }

    #[test]
    fn verify_model_defaults_to_triage_model_when_blank() {
        let tmp = TempDir::new().expect("tempdir");
        let keyring: Arc<dyn KeyringStore> = Arc::new(MockKeyringStore::default());
        let mut settings = settings_fixture();
        settings.verify_model = String::new();
        save_settings(tmp.path(), &settings).expect("save settings");
        save_api_key(tmp.path(), keyring.clone(), FAKE_KEY).expect("save key");

        let cfg = load_config_with(tmp.path(), keyring).expect("load");
        assert_eq!(cfg.verify_model, "deepseek-v4-flash");
    }
}
