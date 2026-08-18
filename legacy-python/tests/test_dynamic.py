"""PoC B2 — DynamicValidator：环回白名单、差分判定、fail-open 记录。"""

from __future__ import annotations

import pytest

from gloscope.dynamic import DynamicValidator, assert_loopback_target
from gloscope.models import Verification

VULN = Verification(
    verdict="confirmed", cwe="CWE-89", confidence="high",
    poc_method="GET", poc_path="/user",
    poc_query="id=' OR '1'='1", poc_body="", poc_signal="admin",
)


class FakeHTTP:
    def __init__(self, poc_text="", neutral_text="", raise_exc=None):
        self.responses = ["poc", "neutral"]
        self.texts = [poc_text, neutral_text]
        self.raise_exc = raise_exc
        self.calls = []

    def __call__(self, method, url, body, headers, timeout):
        # 执行器顺序固定：先 PoC 后基线（编码后 URL 不再含可判标志，按序号分类）
        idx = min(len(self.calls), len(self.responses) - 1)
        kind = self.responses[idx]
        self.calls.append({"kind": kind, "method": method, "url": url,
                           "body": body, "timeout": timeout})
        if self.raise_exc:
            raise self.raise_exc
        return 200, self.texts[idx]


def test_loopback_whitelist():
    assert assert_loopback_target("http://127.0.0.1:5000") == "http://127.0.0.1:5000"
    assert assert_loopback_target("http://localhost:8000/") == "http://localhost:8000"
    assert assert_loopback_target("http://[::1]:9000") == "http://[::1]:9000"
    for bad in ["http://192.168.1.5:5000", "http://example.com",
                "ftp://127.0.0.1", "http://user:pw@127.0.0.1:5000",
                "http://169.254.169.254/latest/meta-data"]:
        with pytest.raises(Exception):
            assert_loopback_target(bad)


def test_reproduced_requires_signal_differential():
    http = FakeHTTP(poc_text="rows: admin", neutral_text="no rows")
    r = DynamicValidator(http=http).check(VULN, "http://127.0.0.1:5000")
    assert r.reproduced is True
    assert "差分成立" in r.evidence
    # 两次请求：PoC 带注入 query，基线值被替换
    poc = next(c for c in http.calls if c["kind"] == "poc")
    neutral = next(c for c in http.calls if c["kind"] == "neutral")
    assert "id=" in poc["url"] and "OR" in poc["url"]
    assert "gloscope-baseline" in neutral["url"]


def test_marker_everywhere_is_not_reproduced():
    http = FakeHTTP(poc_text="admin", neutral_text="admin")  # 信号恒在 → 标记无效
    r = DynamicValidator(http=http).check(VULN, "http://127.0.0.1:5000")
    assert r.reproduced is False
    assert "基线响应=True" in r.evidence


def test_non_confirmed_or_missing_spec_is_skipped():
    http = FakeHTTP()
    v = DynamicValidator(http=http)
    assert v.check(Verification("false_positive", ""), "http://127.0.0.1:5000").reproduced is False
    no_path = Verification("confirmed", "", poc_method="GET", poc_signal="x")
    r = v.check(no_path, "http://127.0.0.1:5000")
    assert r.reproduced is False and "跳过" in r.evidence
    assert http.calls == []


def test_network_failure_recorded_not_raised():
    http = FakeHTTP(raise_exc=TimeoutError("connect timeout"))
    r = DynamicValidator(http=http).check(VULN, "http://127.0.0.1:5000")
    assert r.reproduced is False
    assert r.error and "TimeoutError" in r.error


def test_non_loopback_target_rejected_before_any_request():
    http = FakeHTTP(poc_text="admin", neutral_text="")
    with pytest.raises(Exception, match="环回"):
        DynamicValidator(http=http).check(VULN, "http://10.0.0.1:5000")
    assert http.calls == []  # 校验先于请求


def test_query_with_spaces_is_percent_encoded():
    """实测：agent 给的 poc_query 常含未编码空格/引号（id=' OR '1'='1），
    直接拼 URL 会被 urllib 拒绝（InvalidURL: control characters）。"""
    http = FakeHTTP(poc_text="admin", neutral_text="none")
    DynamicValidator(http=http).check(VULN, "http://127.0.0.1:5000")
    poc = next(c for c in http.calls if c["kind"] == "poc")
    assert " " not in poc["url"] and "'" not in poc["url"]
    assert "%27%20OR%20%271%27=%271" in poc["url"]  # 控制字符编码、k=v 结构保留


def test_post_body_flows_and_neutralized():
    v = Verification(
        verdict="confirmed", cwe="CWE-89", confidence="high",
        poc_method="POST", poc_path="/login", poc_query="",
        poc_body="user=admin'--&pass=x", poc_signal="Welcome")
    http = FakeHTTP(poc_text="Welcome admin", neutral_text="denied")
    r = DynamicValidator(http=http).check(v, "http://127.0.0.1:5000")
    assert r.reproduced is True
    poc = next(c for c in http.calls if c["kind"] == "poc")
    assert poc["method"] == "POST" and "admin'--" in poc["body"]
    neutral = next(c for c in http.calls if c["kind"] == "neutral")
    assert neutral["body"] == "user=gloscope-baseline&pass=gloscope-baseline"
