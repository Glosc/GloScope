"""第二层：便宜模型的 keep/drop 分诊。直接 OpenAI 兼容 chat API 调用，失败 fail-open。"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Callable, TypeAlias
from urllib.parse import urlsplit

from gloscope.config import Config
from gloscope.models import Candidate, TriageResult, asdict_jsonable

# http: (method, url, headers, body, timeout) -> (status, text)。可注入以便测试。
HTTP: TypeAlias = Callable[[str, str, dict, dict, float], "tuple[int, str]"]

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
# base_url 已带版本段（/v1、/v2…）则不再补 /v1；少数网关路径自定义，不做更多猜测
_VERSIONED_SUFFIX_RE = re.compile(r"/v\d+$", re.IGNORECASE)

# 端点来自用户 TOML 配置而非请求输入；此处只做协议白名单，快速暴露配置错误。
# 不阻断私网/环回地址：本地 LLM 服务（如 ollama）是合法端点。
_ALLOWED_SCHEMES = ("https", "http")

PROMPT_TEMPLATE = """你是一名漏洞分诊专家。下面是静态扫描（semgrep）产出的一个候选，
请判断它是否【值得】交给深度验证 agent 追污点链（而不是明显误报）。

判断要点：
- 候选代码是否真的存在把外部输入导向危险 sink 的模式；
- 明显的误报（常量拼接、经过参数化/白名单、测试代码等）应当 drop；
- 拿不准的保留（keep），深度验证层会给出最终结论。

候选 JSON：
{candidate_json}

只输出严格 JSON，不要多余文本：{{"keep": <true|false>, "reason": "<一行中文理由>"}}"""


def _real_http(method: str, url: str, headers: dict, body: dict, timeout: float) -> tuple[int, str]:
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES or not parts.hostname:
        raise ValueError(f"非法 API 端点 {url!r}：仅支持 {'/'.join(_ALLOWED_SCHEMES)} 且需带主机名")
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def chat_completions_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if not _VERSIONED_SUFFIX_RE.search(base):
        base += "/v1"
    return f"{base}/chat/completions"


class OpenAITriageClient:
    def __init__(self, cfg: Config, http: HTTP | None = None) -> None:
        self._cfg = cfg
        self._http = http or _real_http

    def triage(self, candidate: Candidate) -> TriageResult:
        try:
            return self._call(candidate)
        except Exception as e:  # noqa: BLE001 — 分诊层失败必须 fail-open
            return TriageResult(
                keep=True,
                reason=f"triage failed（已保守保留）: {type(e).__name__}: {e}",
                model=self._cfg.triage_model,
            )

    def _call(self, candidate: Candidate) -> TriageResult:
        prompt = PROMPT_TEMPLATE.format(
            candidate_json=json.dumps(asdict_jsonable(candidate), ensure_ascii=False, indent=2)
        )
        body = {
            "model": self._cfg.triage_model,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }
        status, text = self._http(
            "POST",
            chat_completions_url(self._cfg.base_url),
            {"Authorization": f"Bearer {self._cfg.api_key}"},
            body,
            self._cfg.triage_timeout,
        )
        if status != 200:
            raise RuntimeError(f"HTTP {status}: {text[:200]}")
        data = json.loads(text)
        content = str(data["choices"][0]["message"]["content"])
        parsed = json.loads(_FENCE_RE.sub("", content.strip()))
        usage = data.get("usage") or {}
        return TriageResult(
            keep=bool(parsed["keep"]),
            reason=str(parsed.get("reason", "")),
            model=self._cfg.triage_model,
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
        )
