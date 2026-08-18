"""Slice 2 — candidates: semgrep 子进程包装 + JSON 解析 → 候选模型。
接缝：SemgrepCandidateGenerator.run(target)，runner 可注入。

注：fixture 中的 `lines`/`message` 仅为解析样本数据，scanner 语义由 check_id 承载，
片段文本不包含可复用的漏洞构造。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gloscope.models import Candidate
from gloscope.semgrep_runner import BUNDLED_RULES, SemgrepCandidateGenerator, SemgrepError

# 录制的真实 semgrep --json 输出结构（节选自 p/flask 与 p/owasp-top-ten 风格）
SEMGREP_SAMPLE = {
    "version": "1.98.0",
    "errors": [],
    "results": [
        {
            "check_id": "python.flask.security.insecure-sql-query.insecure-sql-query",
            "path": "app.py",
            "start": {"line": 12, "col": 9},
            "end": {"line": 12, "col": 61},
            "extra": {
                "message": "非参数化 SQL 查询可能包含用户输入",
                "lines": "    run_query(dynamically_built_stmt)",
                "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements in SQL"]},
            },
        },
        {
            "check_id": "python.requests.security.requests-ssrf.requests-ssrf",
            "path": "app.py",
            "start": {"line": 20, "col": 13},
            "end": {"line": 20, "col": 37},
            "extra": {
                "message": "Possible SSRF: request target derived from user input",
                "lines": "    r = perform_fetch(unvalidated_target)",
                "metadata": {"cwe": "CWE-918"},
            },
        },
        {
            "check_id": "python.lang.security.audit.path-traversal-open.path-traversal-open",
            "path": "lib/files.py",
            "start": {"line": 27, "col": 5},
            "end": {"line": 27, "col": 25},
            "extra": {
                "message": "Path traversal: opening path joined with user input",
                "lines": "    with open(joined_user_path) as f:",
                "metadata": {},
            },
        },
    ],
}


class FakeRunner:
    """记录 argv，返回预置输出。"""

    def __init__(self, returncode=0, stdout="", stderr="", raise_exc=None):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
        self.raise_exc = raise_exc
        self.calls: list[tuple[list[str], Path]] = []

    def __call__(self, argv, cwd, timeout):
        self.calls.append((list(argv), cwd))
        if self.raise_exc:
            raise self.raise_exc
        return self.returncode, self.stdout, self.stderr


def make_gen(runner):
    return SemgrepCandidateGenerator(runner=runner)


def test_parses_results_into_candidates():
    runner = FakeRunner(stdout=json.dumps(SEMGREP_SAMPLE))
    cands = make_gen(runner).run(Path("target"))
    assert len(cands) == 3
    first = cands[0]
    assert isinstance(first, Candidate)
    assert first.check_id == "python.flask.security.insecure-sql-query.insecure-sql-query"
    assert first.path == "app.py"
    assert first.start_line == 12
    assert first.end_line == 12
    assert first.snippet == "    run_query(dynamically_built_stmt)"  # 原样透传
    assert first.cwe == "CWE-89"  # list 形式 + 冒号描述 → 规范化
    assert cands[1].cwe == "CWE-918"  # 字符串形式直用
    assert cands[2].cwe == "CWE-22"  # 无 metadata → 从 check_id 推断


def test_check_id_category_inference_covers_three_vuln_classes():
    runner = FakeRunner(stdout=json.dumps(SEMGREP_SAMPLE))
    cands = make_gen(runner).run(Path("target"))
    assert cands[0].category == "sql_injection"
    assert cands[1].category == "ssrf"
    assert cands[2].category == "path_traversal"


def test_argv_contains_json_config_and_target():
    runner = FakeRunner(stdout=json.dumps(SEMGREP_SAMPLE))
    make_gen(runner).run(Path("target"))
    argv = runner.calls[0][0]
    assert "--json" in argv
    assert "auto" in argv
    assert "." in argv  # 以 target 为 cwd 扫当前目录 → 输出相对路径
    assert "--no-git-ignore" in argv  # 审计要覆盖保证：gitignored 文件也要扫
    # 盲区补充规则默认与 auto 并联（CVE 回放实测 auto 在两类穿越形态零候选）
    assert BUNDLED_RULES.name in " ".join(argv)
    assert runner.calls[0][1] == Path("target")


def test_custom_semgrep_config_forwarded():
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    SemgrepCandidateGenerator(rules="p/owasp-top-ten", runner=runner).run(Path("t"))
    argv = runner.calls[0][0]
    assert "p/owasp-top-ten" in argv


def test_registry_rule_families_map_to_categories():
    """真实 registry 规则族（p/flask、p/django 同名规则）的类别推断。"""
    sample = {
        "results": [
            {"check_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
             "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
             "extra": {"message": "m", "lines": "s", "metadata": {"cwe": "CWE-704"}}},
            {"check_id": "python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests",
             "path": "app.py", "start": {"line": 27}, "end": {"line": 27},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.django.security.injection.path-traversal.path-traversal-open.path-traversal-open",
             "path": "app.py", "start": {"line": 35}, "end": {"line": 35},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
        ]
    }
    cands = make_gen(FakeRunner(stdout=json.dumps(sample))).run(Path("t"))
    assert [c.category for c in cands] == ["sql_injection", "ssrf", "path_traversal"]


def test_v2_rule_families_map_to_new_categories():
    """v2 类别扩展：pygoat 实测归纳的真实 check_id 样本。"""
    sample = {
        "results": [
            {"check_id": "python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse",
             "path": "views.py", "start": {"line": 290}, "end": {"line": 290},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.django.security.injection.command.subprocess-injection.subprocess-injection",
             "path": "views.py", "start": {"line": 430}, "end": {"line": 430},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use",
             "path": "views.py", "start": {"line": 431}, "end": {"line": 431},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
             "path": "views.py", "start": {"line": 432}, "end": {"line": 432},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.ssti.security.server-side-template-injection",
             "path": "views.py", "start": {"line": 995}, "end": {"line": 995},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.lang.security.audit.eval-detected.eval-detected",
             "path": "views.py", "start": {"line": 1100}, "end": {"line": 1100},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.lang.security.deserialization.pickle.avoid-pickle",
             "path": "views.py", "start": {"line": 1200}, "end": {"line": 1200},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
        ]
    }
    cands = make_gen(FakeRunner(stdout=json.dumps(sample))).run(Path("t"))
    by_line = {c.start_line: c for c in cands}
    assert by_line[290].category == "xss"
    assert by_line[430].cwe == "CWE-78"
    # 430/431/432 同类相邻 → dedup 合一
    assert sorted(c.start_line for c in cands) == [290, 430, 995, 1100, 1200]
    assert by_line[995].category == "ssti"
    assert by_line[1100].category == "code_injection"
    assert by_line[1200].category == "deserialization"


def test_v2_categories_include_regex_dos_and_improper_check():
    """dogfood（Quokka CMS）实测新增类别：regex_dos（CWE-1333）与 improper_check（CWE-706）。"""
    sample = {
        "results": [
            {"check_id": "javascript.lang.security.audit.regex-dos.regex-dos",
             "path": "static/lib.js", "start": {"line": 10}, "end": {"line": 10},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.lang.security.audit.non-literal-import.non-literal-import",
             "path": "app.py", "start": {"line": 50}, "end": {"line": 50},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
        ]
    }
    cands = make_gen(FakeRunner(stdout=json.dumps(sample))).run(Path("t"))
    by_line = {c.start_line: c for c in cands}
    assert by_line[10].category == "regex_dos"
    assert by_line[10].cwe == "CWE-1333"
    assert by_line[50].category == "improper_check"
    assert by_line[50].cwe == "CWE-706"


def test_duplicate_rules_on_same_sink_are_deduped():
    """django/flask 两套 registry 规则常同时命中同一 sink（同行或相邻行）→ 合并为一个候选。"""
    sample = {
        "results": [
            {"check_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
             "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
             "extra": {"message": "flask 版", "lines": "s1", "metadata": {}}},
            {"check_id": "python.django.security.injection.tainted-sql-string.tainted-sql-string",
             "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
             "extra": {"message": "django 版", "lines": "s2", "metadata": {}}},
            {"check_id": "python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests",
             "path": "app.py", "start": {"line": 27}, "end": {"line": 27},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.flask.security.injection.ssrf-requests.ssrf-requests",
             "path": "app.py", "start": {"line": 28}, "end": {"line": 28},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            # 同文件同类但相距远的两个 sink 不合并
            {"check_id": "python.django.security.injection.path-traversal.path-traversal-open.path-traversal-open",
             "path": "app.py", "start": {"line": 35}, "end": {"line": 35},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
            {"check_id": "python.flask.security.audit.path-traversal.path-traversal-open",
             "path": "app.py", "start": {"line": 80}, "end": {"line": 80},
             "extra": {"message": "m", "lines": "s", "metadata": {}}},
        ]
    }
    cands = make_gen(FakeRunner(stdout=json.dumps(sample))).run(Path("t"))
    keys = [(c.path, c.start_line, c.category) for c in cands]
    assert keys == [
        ("app.py", 19, "sql_injection"),
        ("app.py", 27, "ssrf"),
        ("app.py", 35, "path_traversal"),
        ("app.py", 80, "path_traversal"),
    ]


def test_empty_results_yields_empty_list():
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    assert make_gen(runner).run(Path("target")) == []


def test_semgrep_missing_is_clear_error():
    runner = FakeRunner(raise_exc=FileNotFoundError("semgrep"))
    with pytest.raises(SemgrepError, match="semgrep 未安装"):
        make_gen(runner).run(Path("target"))


def test_semgrep_name_resolved_via_pathext(tmp_path, monkeypatch):
    """Windows：npm/venv 工具常是 .cmd/.exe shim，subprocess 不解析裸名 → which 预解析。"""
    monkeypatch.setattr(
        "gloscope.semgrep_runner.shutil.which", lambda n: r"C:\tools\semgrep.EXE"
    )
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    SemgrepCandidateGenerator(semgrep_path="semgrep", runner=runner).run(tmp_path)
    assert runner.calls[0][0][0] == r"C:\tools\semgrep.EXE"
    # which 找不到时保留原名（错误信息由 FileNotFoundError 路径统一给出）
    monkeypatch.setattr("gloscope.semgrep_runner.shutil.which", lambda n: None)
    runner2 = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    SemgrepCandidateGenerator(semgrep_path="semgrep", runner=runner2).run(tmp_path)
    assert runner2.calls[0][0][0] == "semgrep"


def test_nonzero_exit_is_error_with_stderr():
    runner = FakeRunner(returncode=2, stderr="unknown config")
    with pytest.raises(SemgrepError, match="unknown config"):
        make_gen(runner).run(Path("target"))


def test_invalid_json_output_is_error():
    runner = FakeRunner(stdout="not json at all")
    with pytest.raises(SemgrepError, match="JSON"):
        make_gen(runner).run(Path("target"))


def test_snippet_read_from_source_file_not_extra_lines(tmp_path):
    """真实环境实测：semgrep extra.lines 可能返回与代码无关的固定文本（如 'requires login'）。
    候选片段必须以目标源文件为准（唯一事实源），extra.lines 仅作文件缺失时的回退。
    """
    lines = ["line %d" % i for i in range(1, 31)]
    lines[18] = '    query = "SELECT * FROM users WHERE id = \'" + uid + "\'"'  # 第 19 行
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    raw = {
        "results": [
            {"check_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
             "path": "app.py", "start": {"line": 19}, "end": {"line": 19},
             "extra": {"message": "m", "lines": "requires login", "metadata": {}}},
        ]
    }
    cands = make_gen(FakeRunner(stdout=json.dumps(raw))).run(tmp_path)
    assert "SELECT * FROM users" in cands[0].snippet
    assert cands[0].snippet != "requires login"


def test_snippet_falls_back_to_extra_lines_when_file_missing(tmp_path):
    raw = {
        "results": [
            {"check_id": "r", "path": "gone.py", "start": {"line": 3}, "end": {"line": 3},
             "extra": {"message": "m", "lines": "fallback snippet", "metadata": {}}},
        ]
    }
    cands = make_gen(FakeRunner(stdout=json.dumps(raw))).run(tmp_path)
    assert cands[0].snippet == "fallback snippet"


def test_diff_base_limits_semgrep_to_changed_files(tmp_path, monkeypatch):
    """diff-aware 增量扫描：--diff-base 时只把 git 变更文件交给 semgrep。"""
    changed = ["app.py", "lib/util.py", "static/app.js"]
    monkeypatch.setattr(
        "gloscope.semgrep_runner._git_changed_files", lambda target, base: changed
    )
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    SemgrepCandidateGenerator(diff_base="origin/main", runner=runner).run(Path("t"))
    argv = runner.calls[0][0]
    last_cfg = len(argv) - 1 - argv[::-1].index("--config")
    # 最后一个 --config 的值之后：--include *.py + 过滤后的 .py 变更文件
    assert argv[last_cfg + 2:] == ["--include", "*.py", "app.py", "lib/util.py"]


def test_diff_base_git_failure_is_clear_error(tmp_path, monkeypatch):
    def boom(target, base):
        raise RuntimeError("not a git repository")

    monkeypatch.setattr("gloscope.semgrep_runner._git_changed_files", boom)
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    gen = SemgrepCandidateGenerator(diff_base="main", runner=runner)
    with pytest.raises(SemgrepError, match="not a git repository"):
        gen.run(Path("t"))
    assert runner.calls == []  # 失败发生在 semgrep 之前


def test_paths_filter_limits_semgrep_to_explicit_files():
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    SemgrepCandidateGenerator(
        paths=["app.py", "lib/util.py"], runner=runner
    ).run(Path("t"))
    argv = runner.calls[0][0]
    last_cfg = len(argv) - 1 - argv[::-1].index("--config")  # 最后一个 --config 之后是路径段
    assert argv[last_cfg + 2:] == ["app.py", "lib/util.py"]


def test_diff_base_and_paths_are_mutually_exclusive():
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    with pytest.raises(ValueError, match="paths 与 diff_base"):
        SemgrepCandidateGenerator(
            paths=["a.py"], diff_base="main", runner=runner
        )


def test_argv_includes_python_only_by_default():
    """dogfood 实测：semgrep 规则族对 vendored JS 误报极高（108 候选 ~70 来自前端库）。
    默认（含 diff-base）模式加 --include "*.py"；paths 模式不覆盖用户显式清单。"""
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    make_gen(runner).run(Path("t"))
    argv = runner.calls[0][0]
    i = argv.index("--include")
    assert argv[i + 1] == "*.py"


def test_paths_mode_skips_include_filter():
    runner = FakeRunner(stdout=json.dumps({"results": [], "errors": []}))
    SemgrepCandidateGenerator(
        paths=["app.py", "notes.txt"], runner=runner
    ).run(Path("t"))
    argv = runner.calls[0][0]
    assert "--include" not in argv  # 显式清单即用户意图，不替用户过滤
