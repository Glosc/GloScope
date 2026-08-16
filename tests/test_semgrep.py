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
from gloscope.semgrep_runner import SemgrepCandidateGenerator, SemgrepError

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


def test_nonzero_exit_is_error_with_stderr():
    runner = FakeRunner(returncode=2, stderr="unknown config")
    with pytest.raises(SemgrepError, match="unknown config"):
        make_gen(runner).run(Path("target"))


def test_invalid_json_output_is_error():
    runner = FakeRunner(stdout="not json at all")
    with pytest.raises(SemgrepError, match="JSON"):
        make_gen(runner).run(Path("target"))
