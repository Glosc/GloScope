"""MCP A1 — callgraph：stdlib ast 的 best-effort 调用图 + HTTP 入口提取。
接缝：build_callgraph(root) 纯函数，真实形态夹具（Flask 装饰器/Django urls/跨模块调用）。
"""

from __future__ import annotations

from pathlib import Path

from gloscope.callgraph import build_callgraph


def make_fixture(root: Path) -> None:
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    # Flask 形态：装饰器路由 + 跨模块调用（from import 与模块属性两种）
    (root / "app" / "routes.py").write_text(
        """\
from app import services
from app.services import get_user

db = None

@app.route("/user", methods=["POST"])
def user_view():
    uid = "x"
    rows = get_user(uid)
    return services.render(rows)
""",
        encoding="utf-8",
    )
    (root / "app" / "services.py").write_text(
        """\
def get_user(uid):
    return run_query(uid)

def run_query(uid):
    return []
""",
        encoding="utf-8",
    )
    # Django 形态：urls.py path() 绑定 + views 调用
    (root / "app" / "urls.py").write_text(
        """\
from app import views

urlpatterns = [
    path("notes/", views.notes_view),
    path("note/<name>", views.read_note),
]
""",
        encoding="utf-8",
    )
    (root / "app" / "views.py").write_text(
        """\
def notes_view(request):
    return read_note(request)

def read_note(request):
    return {}
""",
        encoding="utf-8",
    )


def test_http_entrypoints_flask_and_django(tmp_path):
    make_fixture(tmp_path)
    g = build_callgraph(tmp_path)
    eps = {(e.method, e.path, e.handler) for e in g.entrypoints}
    assert ("POST", "/user", "app.routes.user_view") in eps
    assert ("GET", "notes/", "app.views.notes_view") in eps
    assert ("GET", "note/<name>", "app.views.read_note") in eps


def test_resolve_finds_definitions(tmp_path):
    make_fixture(tmp_path)
    g = build_callgraph(tmp_path)
    hits = g.resolve("get_user")
    assert any(d.qualname == "app.services.get_user" and d.file == "app/services.py"
               for d in hits)


def test_callees_resolves_import_aliases(tmp_path):
    make_fixture(tmp_path)
    g = build_callgraph(tmp_path)
    callees = {e.callee for e in g.callees("user_view")}
    # from import 的短名调用 → 解析为全限定名
    assert "app.services.get_user" in callees
    # 模块属性调用 → 前缀别名解析
    assert "app.services.render" in callees


def test_callers_traces_both_directions(tmp_path):
    make_fixture(tmp_path)
    g = build_callgraph(tmp_path)
    callers = {e.caller for e in g.callers("get_user")}
    assert "app.routes.user_view" in callers
    # 传递：run_query 的调用者是 app.services.get_user
    assert {e.caller for e in g.callers("run_query")} == {"app.services.get_user"}


def test_syntax_error_files_are_skipped(tmp_path):
    make_fixture(tmp_path)
    (tmp_path / "broken.py").write_text("def (:", encoding="utf-8")
    g = build_callgraph(tmp_path)  # 不抛
    assert g.resolve("get_user")


def test_skip_dirs_and_non_py_ignored(tmp_path):
    make_fixture(tmp_path)
    junk = tmp_path / ".venv" / "lib"
    junk.mkdir(parents=True)
    (junk / "evil.py").write_text("def evil(): pass\n", encoding="utf-8")
    g = build_callgraph(tmp_path)
    assert g.resolve("evil") == []
