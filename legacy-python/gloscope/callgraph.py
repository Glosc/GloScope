"""基于 stdlib ast 的 best-effort 调用图与 HTTP 入口提取。

MCP 工具（http_entrypoints/resolve/callers/callees）的数据源。静态近似：
不做类型推断/动态分发，别名解析覆盖 from-import 与 import-as 两种常见形态；
结果定位是给验证 agent 的辅助索引，agent 仍会读源码确认。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "site-packages"}
MAX_FILES = 2000  # 索引规模上限，超出截断（超大型仓库工具价值本就有限）

_FLASK_ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch"}
_FLASK_METHOD_BY_ATTR = {"route": "GET", "get": "GET", "post": "POST",
                         "put": "PUT", "delete": "DELETE", "patch": "PATCH"}
_DJANGO_PATH_FUNCS = {"path", "re_path", "url"}


@dataclass
class FunctionDef:
    qualname: str
    file: str  # 相对根，正斜杠
    line: int


@dataclass
class CallEdge:
    caller: str
    callee: str
    file: str
    line: int


@dataclass
class HttpEntrypoint:
    method: str
    path: str
    handler: str
    file: str
    line: int


@dataclass
class CallGraph:
    defs: list[FunctionDef] = field(default_factory=list)
    edges: list[CallEdge] = field(default_factory=list)
    entrypoints: list[HttpEntrypoint] = field(default_factory=list)

    def resolve(self, name: str) -> list[FunctionDef]:
        """按全名或短名后缀找定义。"""
        return [d for d in self.defs
                if d.qualname == name or d.qualname.endswith("." + name)]

    def callees(self, func: str) -> list[CallEdge]:
        """func（短名或全名）调用了谁。"""
        return [e for e in self.edges if _qualifies(e.caller, func)]

    def callers(self, func: str) -> list[CallEdge]:
        """谁调用了 func。"""
        return [e for e in self.edges if _qualifies(e.callee, func)]


def _qualifies(qualname: str, query: str) -> bool:
    return qualname == query or qualname.endswith("." + query)


def _module_name(rel_posix: str) -> str:
    parts = rel_posix[:-3].split("/") if rel_posix.endswith(".py") else rel_posix.split("/")
    parts = [p for p in parts if p != "__init__"]
    return ".".join(parts)


def _dotted(node: ast.AST) -> str | None:
    """Name/Attribute 链 → 点分名。"""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _collect_imports(tree: ast.Module) -> dict[str, str]:
    """别名 → 目标点分名。from X import y as z → z: X.y；import X.Y as w → w: X.Y。"""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        elif isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name] = a.name
    return aliases


def _resolve_dotted(name: str, aliases: dict[str, str]) -> str:
    head, _, rest = name.partition(".")
    if head in aliases:
        target = aliases[head]
        return f"{target}.{rest}" if rest else target
    return name


def _flask_entrypoint(decorators: list[ast.expr], qualname: str, file: str,
                      line: int) -> HttpEntrypoint | None:
    for dec in decorators:
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                and dec.func.attr in _FLASK_ROUTE_ATTRS):
            continue
        if not dec.args or not isinstance(dec.args[0], ast.Constant):
            continue
        method = _FLASK_METHOD_BY_ATTR[dec.func.attr]
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                names = [elt.value for elt in kw.value.elts
                         if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
                if names:
                    method = "/".join(sorted(m.upper() for m in names))
        return HttpEntrypoint(method, str(dec.args[0].value), qualname, file, line)
    return None


def _django_entrypoints(tree: ast.Module, module: str, file: str,
                        aliases: dict[str, str]) -> list[HttpEntrypoint]:
    out: list[HttpEntrypoint] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in _DJANGO_PATH_FUNCS):
            continue
        if len(node.args) < 2 or not isinstance(node.args[0], ast.Constant):
            continue
        handler = _dotted(node.args[1])
        if handler is None:
            continue
        route = str(node.args[0].value)
        if node.func.id in ("re_path", "url"):  # 正则路由：去锚点便于人读
            route = route.lstrip("^").rstrip("$")
        out.append(HttpEntrypoint("GET", route, _resolve_dotted(handler, aliases),
                                  file, node.lineno))
    return out


def build_callgraph(root: Path) -> CallGraph:
    root = Path(root)
    py_files = sorted(
        (p for p in root.rglob("*.py")
         if not (SKIP_DIRS & set(p.relative_to(root).parts))),
    )[:MAX_FILES]

    graph = CallGraph()
    parsed: list[tuple[str, str, ast.Module, dict[str, str]]] = []

    for path in py_files:
        rel = path.relative_to(root).as_posix()
        module = _module_name(rel)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        aliases = _collect_imports(tree)
        parsed.append((module, rel, tree, aliases))

        # 定义与 Flask 入口
        class_stack: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_stack.append(node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = f"{module}." + ".".join(class_stack) if class_stack else f"{module}."
                qualname = owner + node.name
                graph.defs.append(FunctionDef(qualname, rel, node.lineno))
                ep = _flask_entrypoint(node.decorator_list, qualname, rel, node.lineno)
                if ep:
                    graph.entrypoints.append(ep)
            # walk 不维护真实作用域栈；类上下文用简化重置（顶层函数内类不计）
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                class_stack = []

        if rel.endswith("urls.py") or rel == "urls.py":
            graph.entrypoints.extend(_django_entrypoints(tree, module, rel, aliases))

    # 调用边（需要全部定义后才能做别名解析一致性）
    for module, rel, tree, aliases in parsed:
        def visit(node: ast.AST, caller: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    visit(child, f"{caller}.{child.name}")
                    continue
                if isinstance(child, ast.Call):
                    dotted = _dotted(child.func)
                    if dotted:
                        graph.edges.append(CallEdge(
                            caller, _resolve_dotted(dotted, aliases), rel, child.lineno))
                visit(child, caller)
        visit(tree, module)

    return graph
