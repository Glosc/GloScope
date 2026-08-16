"""MCP A2 — 最小 MCP stdio server：4 个调用图工具，进程内可测。

协议子集：initialize / notifications/* / ping / tools/list / tools/call，
换行分隔 JSON-RPC 2.0。手写实现保持零第三方依赖（mcp SDK 拖 pydantic 全家桶）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from gloscope import __version__
from gloscope.callgraph import build_callgraph

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "http_entrypoints",
        "description": "列出目标仓库全部 HTTP 入口（Flask 装饰器与 Django urls.py）："
                       "method、path、handler 全限定名、file:line。验证路由可达性从这开始。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "resolve",
        "description": "按短名或全限定名解析函数/方法定义位置（file:line），"
                       "含 from-import 别名归一。",
        "inputSchema": {"type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"]},
    },
    {
        "name": "callers",
        "description": "谁调用了指定函数（best-effort 静态调用边）。",
        "inputSchema": {"type": "object",
                        "properties": {"func": {"type": "string"}},
                        "required": ["func"]},
    },
    {
        "name": "callees",
        "description": "指定函数调用了谁（best-effort 静态调用边）。",
        "inputSchema": {"type": "object",
                        "properties": {"func": {"type": "string"}},
                        "required": ["func"]},
    },
]


def _tool_text(graph, name: str, args: dict) -> str:
    if name == "http_entrypoints":
        eps = graph.entrypoints
        if not eps:
            return "（未发现 HTTP 入口）"
        return "\n".join(
            f"{e.method:<10} {e.path:<28} {e.handler} ({e.file}:{e.line})"
            for e in eps
        )
    if name == "resolve":
        hits = graph.resolve(str(args.get("name", "")))
        if not hits:
            return "（无匹配定义）"
        return "\n".join(f"{d.qualname} ({d.file}:{d.line})" for d in hits)
    if name == "callers":
        edges = graph.callers(str(args.get("func", "")))
        if not edges:
            return "（无调用者记录）"
        return "\n".join(f"{e.caller} ({e.file}:{e.line})" for e in edges)
    if name == "callees":
        edges = graph.callees(str(args.get("func", "")))
        if not edges:
            return "（无被调记录）"
        return "\n".join(f"{e.callee} ({e.file}:{e.line})" for e in edges)
    raise KeyError(f"unknown tool: {name}")


def serve(target: Path, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    """逐行读取 JSON-RPC，应答写回 stdout。target 在启动时索引一次。"""
    graph = build_callgraph(Path(target))

    def reply(msg_id, result) -> None:
        stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result},
                                ensure_ascii=False) + "\n")
        stdout.flush()

    def reply_error(msg_id, code, message) -> None:
        stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                                 "error": {"code": code, "message": message}},
                                ensure_ascii=False) + "\n")
        stdout.flush()

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method", "")
        msg_id = msg.get("id")
        if method.startswith("notifications/"):
            continue
        if method == "initialize":
            reply(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "gloscope-callgraph", "version": __version__},
            })
        elif method == "ping":
            reply(msg_id, {})
        elif method == "tools/list":
            reply(msg_id, {"tools": _TOOLS})
        elif method == "tools/call":
            try:
                text = _tool_text(graph, msg["params"]["name"], msg["params"].get("arguments") or {})
                reply(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
            except Exception as e:  # noqa: BLE001 — 工具错误以 isError 返回，不让 server 崩
                reply(msg_id, {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                               "isError": True})
        elif msg_id is not None:
            reply_error(msg_id, -32601, f"method not found: {method}")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python -m gloscope.mcp_server <target-root>", file=sys.stderr)
        return 2
    serve(Path(argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
