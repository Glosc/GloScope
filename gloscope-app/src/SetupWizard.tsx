import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type GloscopeSettings = {
  base_url: string;
  triage_model: string;
  verify_model: string;
  wire_api: string;
  triage_timeout_secs: number;
  verify_timeout_secs: number;
};

const DEFAULT_SETTINGS: GloscopeSettings = {
  base_url: "https://api.deepseek.com",
  triage_model: "deepseek-v4-flash",
  verify_model: "deepseek-v4-pro",
  wire_api: "responses",
  triage_timeout_secs: 60,
  verify_timeout_secs: 600,
};

type Props = {
  onConfigured: () => void;
};

/// First-run wizard: collects provider base_url + models (non-secret,
/// persisted to ~/.gloscope/settings.toml) and the API key (persisted to the
/// OS keyring, never re-displayed once saved). Also reachable later to edit
/// settings — in that case the API key field is left blank and only
/// overwrites the stored key if the user types a new one.
function SetupWizard({ onConfigured }: Props) {
  const [settings, setSettings] = useState<GloscopeSettings>(DEFAULT_SETTINGS);
  const [apiKey, setApiKey] = useState("");
  const [hasStoredKey, setHasStoredKey] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<GloscopeSettings>("gloscope_load_settings")
      .then((loaded) => setSettings(loaded))
      .catch(() => {
        /* not configured yet: keep defaults */
      });
    invoke<boolean>("gloscope_has_api_key")
      .then(setHasStoredKey)
      .catch(() => setHasStoredKey(false));
  }, []);

  function update<K extends keyof GloscopeSettings>(key: K, value: GloscopeSettings[K]) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!settings.base_url.trim() || !settings.triage_model.trim()) {
      setError("Base URL 和 Triage model 是必填项");
      return;
    }
    if (!hasStoredKey && !apiKey.trim()) {
      setError("请填写 API key");
      return;
    }

    setSaving(true);
    try {
      await invoke("gloscope_save_settings", { settings });
      if (apiKey.trim()) {
        await invoke("gloscope_save_api_key", { apiKey: apiKey.trim() });
      }
      await invoke("gloscope_start_session");
      onConfigured();
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="container wizard">
      <h1>GloScope 设置</h1>
      <p className="wizard__intro">
        填写一次即可扫描任意仓库。API key 会保存在系统密钥链中，不会以明文写入磁盘。
      </p>
      <form className="wizard__form" onSubmit={handleSubmit}>
        <label className="wizard__field">
          <span>Base URL</span>
          <input
            value={settings.base_url}
            onChange={(e) => update("base_url", e.currentTarget.value)}
            placeholder="https://api.deepseek.com"
          />
        </label>
        <label className="wizard__field">
          <span>API key {hasStoredKey && <em>(已保存，留空则不修改)</em>}</span>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.currentTarget.value)}
            placeholder={hasStoredKey ? "••••••••" : "sk-..."}
          />
        </label>
        <label className="wizard__field">
          <span>Triage model（分诊，便宜模型）</span>
          <input
            value={settings.triage_model}
            onChange={(e) => update("triage_model", e.currentTarget.value)}
            placeholder="deepseek-v4-flash"
          />
        </label>
        <label className="wizard__field">
          <span>Verify model（深度验证）</span>
          <input
            value={settings.verify_model}
            onChange={(e) => update("verify_model", e.currentTarget.value)}
            placeholder="deepseek-v4-pro"
          />
        </label>

        <button
          type="button"
          className="wizard__advanced-toggle"
          onClick={() => setShowAdvanced((prev) => !prev)}
        >
          {showAdvanced ? "隐藏高级选项" : "显示高级选项"}
        </button>
        {showAdvanced && (
          <div className="wizard__advanced">
            <label className="wizard__field">
              <span>Wire API</span>
              <input
                value={settings.wire_api}
                onChange={(e) => update("wire_api", e.currentTarget.value)}
              />
            </label>
            <label className="wizard__field">
              <span>Triage timeout (秒)</span>
              <input
                type="number"
                value={settings.triage_timeout_secs}
                onChange={(e) => update("triage_timeout_secs", Number(e.currentTarget.value))}
              />
            </label>
            <label className="wizard__field">
              <span>Verify timeout (秒)</span>
              <input
                type="number"
                value={settings.verify_timeout_secs}
                onChange={(e) => update("verify_timeout_secs", Number(e.currentTarget.value))}
              />
            </label>
          </div>
        )}

        {error && <div className="wizard__error">{error}</div>}

        <button type="submit" disabled={saving} className="wizard__submit">
          {saving ? "保存中..." : "保存并开始"}
        </button>
      </form>
    </main>
  );
}

export default SetupWizard;
