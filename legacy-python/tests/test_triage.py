"""Slice 3 — triage: OpenAI 兼容分诊调用（keep/drop + 理由），任何失败 fail-open 保留。
接缝：OpenAITriageClient.triage(candidate)，http 可注入。
"""

from __future__ import annotations

import json

import pytest

from gloscope.config import Config
from gloscope.models import Candidate
from gloscope.triage import OpenAITriageClient

CFG = Config(
    base_url="https://api.deepseek.com",
    api_key="sk-test",
    triage_model="deepseek-chat",
    verify_model="deepseek-reasoner",
)

CAND = Candidate(
    check_id="python.flask.security.insecure-sql-query.insecure-sql-query",
    path="app.py",
    start_line=12,
    end_line=12,
    snippet="    run_query(dynamically_built_stmt)",
    message="非参数化 SQL 查询",
    cwe="CWE-89",
    category="sql_injection",
)


class FakeHTTP:
    def __init__(self, status=200, content='{"keep": false, "reason": "明显误报"}', usage=(10, 5), raise_exc=None):
        self.status, self.content, self.usage = status, content, usage
        self.raise_exc = raise_exc
        self.last: dict | None = None

    def __call__(self, method, url, headers, body, timeout):
        self.last = {"method": method, "url": url, "headers": headers,
                     "body": body, "timeout": timeout}
        if self.raise_exc:
            raise self.raise_exc
        payload = {
            "choices": [{"message": {"content": self.content}}],
            "usage": {"prompt_tokens": self.usage[0], "completion_tokens": self.usage[1]},
        }
        return self.status, json.dumps(payload)


def make_client(http):
    return OpenAITriageClient(CFG, http=http)


def test_request_shape_and_url_normalization():
    http = FakeHTTP()
    make_client(http).triage(CAND)
    assert http.last["method"] == "POST"
    # base_url 不带 /v1 时补全
    assert http.last["url"] == "https://api.deepseek.com/v1/chat/completions"
    assert http.last["headers"]["Authorization"] == "Bearer sk-test"
    body = http.last["body"]
    assert body["model"] == "deepseek-chat"
    prompt = body["messages"][-1]["content"]
    # 自包含：候选的关键字段都进了 prompt，且要求严格 JSON 输出
    assert CAND.check_id in prompt
    assert "app.py" in prompt
    assert "12" in prompt
    assert "JSON" in prompt


def test_url_with_explicit_v1_not_duplicated():
    http = FakeHTTP()
    cfg = Config("https://x.example/v1", "sk", "m", "m")
    OpenAITriageClient(cfg, http=http).triage(CAND)
    assert http.last["url"] == "https://x.example/v1/chat/completions"


def test_parses_keep_drop_with_usage():
    http = FakeHTTP(content='{"keep": false, "reason": "常量拼接，无用户输入"}')
    r = make_client(http).triage(CAND)
    assert r.keep is False
    assert r.reason == "常量拼接，无用户输入"
    assert r.model == "deepseek-chat"
    assert (r.tokens_in, r.tokens_out) == (10, 5)


def test_strips_markdown_fences():
    http = FakeHTTP(content='```json\n{"keep": true, "reason": "需要深查"}\n```')
    r = make_client(http).triage(CAND)
    assert r.keep is True
    assert r.reason == "需要深查"


def test_bad_content_json_fails_open_to_keep():
    http = FakeHTTP(content="I think this is a real issue")  # 非 JSON
    r = make_client(http).triage(CAND)
    assert r.keep is True
    assert "triage failed" in r.reason


def test_http_error_fails_open_to_keep():
    http = FakeHTTP(status=500, content="boom")
    r = make_client(http).triage(CAND)
    assert r.keep is True
    assert "triage failed" in r.reason


def test_timeout_fails_open_to_keep():
    http = FakeHTTP(raise_exc=TimeoutError("read timeout"))
    r = make_client(http).triage(CAND)
    assert r.keep is True
    assert "triage failed" in r.reason


def test_url_tolerates_versioned_and_full_endpoints():
    from gloscope.triage import chat_completions_url

    assert chat_completions_url("https://x.example/v2") == "https://x.example/v2/chat/completions"
    assert chat_completions_url("https://x.example/api/v1") == "https://x.example/api/v1/chat/completions"
    assert chat_completions_url("https://x/v1/chat/completions") == "https://x/v1/chat/completions"
