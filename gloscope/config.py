"""TOML 单文件配置：provider（两层共用）+ 模型分级 + 可选限额。"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILENAMES = ("gloscope.toml", "config.local.toml")


class ConfigError(RuntimeError):
    """配置缺失或非法。"""


@dataclass
class Config:
    base_url: str
    api_key: str
    triage_model: str
    verify_model: str
    # codex 0.147+ 仅支持 "responses"（model_providers 的 chat 已移除）；
    # 分诊层不受影响（直连 chat completions）
    wire_api: str = "responses"
    triage_timeout: float = 60.0
    verify_timeout: float = 600.0


def _find_config_file() -> Path | None:
    env = os.environ.get("GLOSCOPE_CONFIG")
    if env:
        p = Path(env)
        if not p.is_file():
            raise ConfigError(f"GLOSCOPE_CONFIG 指向的文件不存在: {p}")
        return p
    for name in CONFIG_FILENAMES:
        p = Path.cwd() / name
        if p.is_file():
            return p
    return None


def load_config(path: Path | str | None = None) -> Config:
    """加载配置；path 为空时按 GLOSCOPE_CONFIG → ./gloscope.toml → ./config.local.toml 发现。"""
    if path is not None:
        cfg_path = Path(path)
        if not cfg_path.is_file():
            raise ConfigError(f"配置文件不存在: {cfg_path}")
    else:
        found = _find_config_file()
        if found is None:
            raise ConfigError(
                "未找到配置文件：请用 --config 指定，或在当前目录放置 "
                f"{' / '.join(CONFIG_FILENAMES)}（模板见 README）"
            )
        cfg_path = found

    raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    provider = raw.get("provider", {})
    models = raw.get("models", {})
    limits = raw.get("limits", {})

    base_url = provider.get("base_url")
    if not base_url:
        raise ConfigError("配置缺少 [provider] base_url")
    api_key = provider.get("api_key") or os.environ.get("GLOSCOPE_API_KEY")
    if not api_key:
        raise ConfigError(
            "配置缺少 [provider] api_key（也可用环境变量 GLOSCOPE_API_KEY）"
        )
    triage_model = models.get("triage_model")
    if not triage_model:
        raise ConfigError("配置缺少 [models] triage_model")

    return Config(
        base_url=str(base_url),
        api_key=str(api_key),
        triage_model=str(triage_model),
        verify_model=str(models.get("verify_model") or triage_model),
        wire_api=str(provider.get("wire_api", "responses")),
        triage_timeout=float(limits.get("triage_timeout", 60.0)),
        verify_timeout=float(limits.get("verify_timeout", 600.0)),
    )
