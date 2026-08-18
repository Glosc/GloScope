//! GloScope-specific configuration: provider credentials + model tiers.
//! Ported from `legacy-python/gloscope/config.py`. Deliberately independent
//! of codex's own `Config`/`model_providers`: GloScope's provider is injected
//! into a *nested* `codex exec` subprocess's isolated `CODEX_HOME` (see
//! `submit_verdict::write_codex_home`), not the host session's own provider
//! set, so there is no meaningful config to share between the two.

use serde::Deserialize;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

const CONFIG_FILENAMES: [&str; 2] = ["gloscope.toml", "config.local.toml"];

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("GLOSCOPE_CONFIG 指向的文件不存在: {}", .0.display())]
    EnvPathNotFound(PathBuf),
    #[error(
        "未找到配置文件：请在目标仓库根目录放置 gloscope.toml / config.local.toml，\
         或设置 GLOSCOPE_CONFIG 指向配置文件"
    )]
    NotFound,
    #[error("读取配置文件失败: {0}")]
    Read(String),
    #[error("配置文件不是合法 TOML: {0}")]
    InvalidToml(String),
    #[error("配置缺少 [provider] base_url")]
    MissingBaseUrl,
    #[error("配置缺少 [provider] api_key（也可用环境变量 GLOSCOPE_API_KEY）")]
    MissingApiKey,
    #[error("配置缺少 [models] triage_model")]
    MissingTriageModel,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GloscopeConfig {
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    /// Consumed by the future `triage` tool (M5); unused until then.
    #[allow(dead_code)]
    pub(crate) triage_model: String,
    pub(crate) verify_model: String,
    pub(crate) wire_api: String,
    /// Consumed by the future `triage` tool (M5); unused until then.
    #[allow(dead_code)]
    pub(crate) triage_timeout: Duration,
    pub(crate) verify_timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawConfig {
    provider: RawProvider,
    models: RawModels,
    limits: RawLimits,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            provider: RawProvider::default(),
            models: RawModels::default(),
            limits: RawLimits::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawProvider {
    base_url: Option<String>,
    api_key: Option<String>,
    wire_api: String,
}

impl Default for RawProvider {
    fn default() -> Self {
        Self {
            base_url: None,
            api_key: None,
            wire_api: "responses".to_string(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawModels {
    triage_model: Option<String>,
    verify_model: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawLimits {
    triage_timeout: f64,
    verify_timeout: f64,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            triage_timeout: 60.0,
            verify_timeout: 600.0,
        }
    }
}

fn find_config_file(target: &Path) -> Result<Option<PathBuf>, ConfigError> {
    if let Ok(env_path) = std::env::var("GLOSCOPE_CONFIG") {
        let path = PathBuf::from(env_path);
        if !path.is_file() {
            return Err(ConfigError::EnvPathNotFound(path));
        }
        return Ok(Some(path));
    }
    for name in CONFIG_FILENAMES {
        let path = target.join(name);
        if path.is_file() {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Loads GloScope's provider/model config, searching (in order) the
/// `GLOSCOPE_CONFIG` env var, then `<target>/gloscope.toml`, then
/// `<target>/config.local.toml`.
pub(crate) fn load_config(target: &Path) -> Result<GloscopeConfig, ConfigError> {
    let path = find_config_file(target)?.ok_or(ConfigError::NotFound)?;
    let text =
        std::fs::read_to_string(&path).map_err(|err| ConfigError::Read(err.to_string()))?;
    let raw: RawConfig =
        toml::from_str(&text).map_err(|err| ConfigError::InvalidToml(err.to_string()))?;

    let base_url = raw.provider.base_url.ok_or(ConfigError::MissingBaseUrl)?;
    let api_key = raw
        .provider
        .api_key
        .or_else(|| std::env::var("GLOSCOPE_API_KEY").ok())
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::MissingApiKey)?;
    let triage_model = raw
        .models
        .triage_model
        .ok_or(ConfigError::MissingTriageModel)?;
    let verify_model = raw.models.verify_model.unwrap_or_else(|| triage_model.clone());

    Ok(GloscopeConfig {
        base_url,
        api_key,
        triage_model,
        verify_model,
        wire_api: raw.provider.wire_api,
        triage_timeout: Duration::from_secs_f64(raw.limits.triage_timeout),
        verify_timeout: Duration::from_secs_f64(raw.limits.verify_timeout),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const FAKE_KEY: &str = "fake-key-for-unit-tests";

    fn write_config(dir: &Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).expect("write config");
    }

    #[test]
    fn loads_full_config_with_overrides() {
        let tmp = TempDir::new().expect("tempdir");
        write_config(
            tmp.path(),
            "gloscope.toml",
            &format!(
                "[provider]\nbase_url = \"https://api.deepseek.com\"\napi_key = \"{FAKE_KEY}\"\nwire_api = \"responses\"\n\n[models]\ntriage_model = \"deepseek-chat\"\nverify_model = \"deepseek-reasoner\"\n\n[limits]\ntriage_timeout = 30.0\nverify_timeout = 120.0\n"
            ),
        );
        let cfg = load_config(tmp.path()).expect("loads");
        assert_eq!(cfg.base_url, "https://api.deepseek.com");
        assert_eq!(cfg.api_key, FAKE_KEY);
        assert_eq!(cfg.triage_model, "deepseek-chat");
        assert_eq!(cfg.verify_model, "deepseek-reasoner");
        assert_eq!(cfg.verify_timeout, Duration::from_secs_f64(120.0));
    }

    #[test]
    fn verify_model_defaults_to_triage_model() {
        let tmp = TempDir::new().expect("tempdir");
        write_config(
            tmp.path(),
            "gloscope.toml",
            &format!(
                "[provider]\nbase_url = \"https://api.deepseek.com\"\napi_key = \"{FAKE_KEY}\"\n\n[models]\ntriage_model = \"deepseek-chat\"\n"
            ),
        );
        let cfg = load_config(tmp.path()).expect("loads");
        assert_eq!(cfg.verify_model, "deepseek-chat");
        assert_eq!(cfg.wire_api, "responses");
        assert_eq!(cfg.verify_timeout, Duration::from_secs_f64(600.0));
    }

    #[test]
    fn missing_config_file_is_clear_error() {
        let tmp = TempDir::new().expect("tempdir");
        let err = load_config(tmp.path()).expect_err("should error");
        assert!(matches!(err, ConfigError::NotFound));
    }

    #[test]
    fn missing_base_url_is_clear_error() {
        let tmp = TempDir::new().expect("tempdir");
        write_config(
            tmp.path(),
            "gloscope.toml",
            "[models]\ntriage_model = \"deepseek-chat\"\n",
        );
        let err = load_config(tmp.path()).expect_err("should error");
        assert!(matches!(err, ConfigError::MissingBaseUrl));
    }

    #[test]
    fn api_key_falls_back_to_env_var() {
        let tmp = TempDir::new().expect("tempdir");
        write_config(
            tmp.path(),
            "gloscope.toml",
            "[provider]\nbase_url = \"https://api.deepseek.com\"\n\n[models]\ntriage_model = \"deepseek-chat\"\n",
        );
        // SAFETY: single-threaded test process; no concurrent env access.
        unsafe {
            std::env::set_var("GLOSCOPE_API_KEY", FAKE_KEY);
        }
        let result = load_config(tmp.path());
        unsafe {
            std::env::remove_var("GLOSCOPE_API_KEY");
        }
        assert_eq!(result.expect("loads").api_key, FAKE_KEY);
    }

    #[test]
    fn config_local_toml_is_used_when_gloscope_toml_absent() {
        let tmp = TempDir::new().expect("tempdir");
        write_config(
            tmp.path(),
            "config.local.toml",
            &format!(
                "[provider]\nbase_url = \"https://api.deepseek.com\"\napi_key = \"{FAKE_KEY}\"\n\n[models]\ntriage_model = \"deepseek-chat\"\n"
            ),
        );
        let cfg = load_config(tmp.path()).expect("loads");
        assert_eq!(cfg.base_url, "https://api.deepseek.com");
    }
}
