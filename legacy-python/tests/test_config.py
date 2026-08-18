"""Slice 1 — config: TOML 加载、环境变量回退、校验错误。接缝：load_config 公开函数。"""

from __future__ import annotations

import pytest

from gloscope.config import Config, ConfigError, load_config


def _write(tmp_path, name: str, text: str):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


FULL = """
[provider]
base_url = "https://api.deepseek.com"
api_key = "sk-test"

[models]
triage_model = "deepseek-chat"
verify_model = "deepseek-reasoner"
"""


def test_load_full_config(tmp_path):
    p = _write(tmp_path, "gloscope.toml", FULL)
    cfg = load_config(p)
    assert cfg == Config(
        base_url="https://api.deepseek.com",
        api_key="sk-test",
        triage_model="deepseek-chat",
        verify_model="deepseek-reasoner",
    )


def test_verify_model_defaults_to_triage_model(tmp_path):
    p = _write(
        tmp_path,
        "gloscope.toml",
        """
[provider]
base_url = "https://api.deepseek.com"
api_key = "sk-test"

[models]
triage_model = "deepseek-chat"
""",
    )
    cfg = load_config(p)
    assert cfg.verify_model == "deepseek-chat"


def test_api_key_env_fallback(tmp_path, monkeypatch):
    p = _write(
        tmp_path,
        "gloscope.toml",
        """
[provider]
base_url = "https://api.deepseek.com"

[models]
triage_model = "deepseek-chat"
""",
    )
    monkeypatch.setenv("GLOSCOPE_API_KEY", "sk-from-env")
    cfg = load_config(p)
    assert cfg.api_key == "sk-from-env"


def test_missing_api_key_is_error(tmp_path, monkeypatch):
    monkeypatch.delenv("GLOSCOPE_API_KEY", raising=False)
    p = _write(
        tmp_path,
        "gloscope.toml",
        """
[provider]
base_url = "https://api.deepseek.com"

[models]
triage_model = "deepseek-chat"
""",
    )
    with pytest.raises(ConfigError, match="api_key"):
        load_config(p)


@pytest.mark.parametrize(
    "body,frag",
    [
        ('[provider]\nbase_url = "https://x"\napi_key = "sk"\n', "models"),  # 缺 [models]
        ('[provider]\napi_key = "sk"\n\n[models]\ntriage_model = "m"\n', "base_url"),  # 缺 base_url
        ("[models]\ntriage_model = 'm'\n", "provider"),  # 缺 [provider]
    ],
)
def test_required_fields_reported(tmp_path, monkeypatch, body, frag):
    monkeypatch.delenv("GLOSCOPE_API_KEY", raising=False)
    p = _write(tmp_path, "gloscope.toml", body)
    with pytest.raises(ConfigError, match=frag):
        load_config(p)


def test_discovery_prefers_explicit_then_gloscope_then_local(tmp_path, monkeypatch):
    # cwd 下发现 gloscope.toml
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "gloscope.toml", FULL)
    cfg = load_config(None)
    assert cfg.triage_model == "deepseek-chat"

    # 显式路径优先于 cwd 发现
    other = tmp_path / "other.toml"
    other.write_text(
        '[provider]\nbase_url = "https://x"\napi_key = "sk"\n\n[models]\ntriage_model = "explicit"\n',
        encoding="utf-8",
    )
    assert load_config(other).triage_model == "explicit"

    # 其次 config.local.toml
    (tmp_path / "gloscope.toml").unlink()
    _write(
        tmp_path,
        "config.local.toml",
        '[provider]\nbase_url = "https://x"\napi_key = "sk"\n\n[models]\ntriage_model = "local"\n',
    )
    assert load_config(None).triage_model == "local"


def test_no_config_found_is_clear_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GLOSCOPE_CONFIG", raising=False)
    with pytest.raises(ConfigError, match="未找到配置文件"):
        load_config(None)
