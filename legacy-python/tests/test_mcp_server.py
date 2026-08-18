"""MCP A2 — mcp_server：进程内协议测试（假 stdin/stdout）。"""

from __future__ import annotations

import io
import json
from pathlib import Path

from gloscope.mcp_server import serve
from tests.test_callgraph import make_fixture


class Chan:
    def __init__(self, lines: list[str]):
        self._in = io.StringIO("\n".join(lines) + "\n")
        self.out = io.StringIO()

    @property
    def replies(self) -> list[dict]:
        return [json.loads(l) for l in self.out.getvalue().splitlines() if l.strip()]


def rpc(msg_id, method, params=None):
    msg = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def run(tmp_path: Path, lines: list[str]) -> list[dict]:
    make_fixture(tmp_path)
    chan = Chan(lines)
    serve(tmp_path, stdin=chan._in, stdout=chan.out)
    return chan.replies


def test_initialize_ping_and_notification_silence(tmp_path):
    replies = run(tmp_path, [
        rpc(1, "initialize", {"protocolVersion": "2024-11-05"}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        rpc(2, "ping"),
    ])
    by_id = {r["id"]: r for r in replies}
    assert by_id[1]["result"]["protocolVersion"] == "2024-11-05"
    assert "tools" in by_id[1]["result"]["capabilities"]
    assert by_id[2]["result"] == {}
    assert len(replies) == 2  # notification 不回包


def test_tools_list_exposes_four_tools(tmp_path):
    replies = run(tmp_path, [rpc(1, "tools/list")])
    tools = {t["name"] for t in replies[0]["result"]["tools"]}
    assert tools == {"http_entrypoints", "resolve", "callers", "callees"}


def test_tools_call_returns_entrypoints_and_resolve(tmp_path):
    replies = run(tmp_path, [
        rpc(1, "tools/call", {"name": "http_entrypoints", "arguments": {}}),
        rpc(2, "tools/call", {"name": "resolve", "arguments": {"name": "get_user"}}),
        rpc(3, "tools/call", {"name": "callers", "arguments": {"func": "run_query"}}),
        rpc(4, "tools/call", {"name": "callees", "arguments": {"func": "user_view"}}),
    ])
    texts = [r["result"]["content"][0]["text"] for r in replies]
    assert all(r["result"]["isError"] is False for r in replies)
    assert "POST" in texts[0] and "/user" in texts[0] and "app.routes.user_view" in texts[0]
    assert "app.services.get_user" in texts[1]
    assert "app.services.get_user" in texts[2]  # run_query 的调用者
    assert "app.services.render" in texts[3]


def test_unknown_method_and_tool_error(tmp_path):
    replies = run(tmp_path, [
        rpc(1, "bogus/method"),
        rpc(2, "tools/call", {"name": "no_such_tool", "arguments": {}}),
    ])
    assert replies[0]["error"]["code"] == -32601
    assert replies[1]["result"]["isError"] is True
