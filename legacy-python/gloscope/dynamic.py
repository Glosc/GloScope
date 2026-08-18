"""PoC B2 — DynamicValidator：声明式 HTTP PoC 的差分执行器。

安全边界（用户批准的设计，2026-08-17）：目标必须显式传入且 host 硬编码环回
白名单（127.0.0.1/::1/localhost，localhost 需 DNS 解析后全为环回）；
仅 http/https；禁跨域重定向；PoC 是请求规格而非可执行代码。
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, TypeAlias
from urllib.parse import quote, urlsplit, urlunsplit

from gloscope.models import Verification

# http: (method, url, body, headers, timeout) -> (status, text)。可注入以便测试。
HTTP: TypeAlias = Callable[[str, str, str, dict, float], "tuple[int, str]"]

_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}
_BASELINE_VALUE = "gloscope-baseline"


class DynamicError(RuntimeError):
    """动态校验前置条件不满足（非环回目标/非法 URL 等）。"""


@dataclass
class DynamicResult:
    reproduced: bool
    evidence: str
    error: str | None = None


def assert_loopback_target(base_url: str) -> str:
    """校验并规范化目标 URL：仅 http/https、host 必须环回、禁 userinfo。"""
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise DynamicError(f"仅允许 http/https 目标: {base_url!r}")
    host = (parts.hostname or "").strip("[]").lower()
    if parts.username or parts.password:
        raise DynamicError("目标 URL 不允许携带 userinfo")
    if host == "localhost":
        import socket
        infos = socket.getaddrinfo("localhost", parts.port or 80)
        for info in infos:
            if info[4][0] not in _LOOPBACK_HOSTS:
                raise DynamicError("localhost 解析出非环回地址，拒绝执行")
    elif host not in _LOOPBACK_HOSTS:
        raise DynamicError(
            f"目标必须是环回地址（{'/'.join(sorted(_LOOPBACK_HOSTS))}）: {host!r}"
        )
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _encode_query(params: str) -> str:
    """对 agent 给的注入串做百分号编码（保留 & = 结构）。

    agent 可能给原始串（id=' OR '1'='1）或已编码串（name=..%2Fapp.py）：
    已含 %XX 的按已编码处理（避免双重编码），否则编码控制字符。
    """
    if re.search(r"%[0-9A-Fa-f]{2}", params):
        return params
    return quote(params, safe="=&")


def _neutralize(params: str) -> str:
    """k=v&k2=v2 → 每个值替换为基线值（差分对照请求）。"""
    if not params:
        return ""
    out = []
    for pair in params.split("&"):
        key, _, _ = pair.partition("=")
        out.append(f"{key}={_BASELINE_VALUE}")
    return "&".join(out)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None  # 3xx 原样返回，禁止跟随（防跳出环回白名单）


def _real_http(method: str, url: str, body: str, headers: dict,
               timeout: float) -> tuple[int, str]:
    """执行前置已过环回白名单的请求；3xx 不跟随。"""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        url, data=body.encode("utf-8") if body else None,
        headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:  # 4xx/5xx/3xx：作为响应体处理（差分信号仍可判）
        return e.code, e.read().decode("utf-8", errors="replace")


class DynamicValidator:
    def __init__(self, http: HTTP | None = None, timeout: float = 10.0) -> None:
        self._http = http or _real_http
        self._timeout = timeout

    def check(self, v: Verification, base_url: str) -> DynamicResult:
        base = assert_loopback_target(base_url)
        if v.verdict != "confirmed" or not v.poc_path or not v.poc_method:
            return DynamicResult(False, "跳过（非 confirmed 或无 PoC 请求规格）")
        if not v.poc_signal:
            return DynamicResult(False, "跳过（PoC 规格缺差分信号）")

        url = base + v.poc_path
        if v.poc_query:
            url += "?" + _encode_query(v.poc_query)
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if v.poc_body else {}
        try:
            poc_status, poc_text = self._http(
                v.poc_method, url, v.poc_body, headers, self._timeout)
            neutral_url = base + v.poc_path
            if v.poc_query:
                neutral_url += "?" + _neutralize(v.poc_query)
            neutral_body = _neutralize(v.poc_body) if v.poc_body else ""
            _, neutral_text = self._http(
                v.poc_method, neutral_url, neutral_body, headers, self._timeout)
        except Exception as e:  # noqa: BLE001 — 网络失败不外抛，记录为错误
            return DynamicResult(False, "", error=f"{type(e).__name__}: {e}")

        if v.poc_signal in poc_text and v.poc_signal not in neutral_text:
            return DynamicResult(
                True,
                f"PoC 响应含信号 {v.poc_signal!r}（status {poc_status}），"
                f"基线响应不含——差分成立",
            )
        return DynamicResult(
            False,
            f"未复现：信号在 PoC 响应={v.poc_signal in poc_text}，"
            f"在基线响应={v.poc_signal in neutral_text}",
        )
