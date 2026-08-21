"""CVE 回放 harness 核心逻辑：案例加载、版本装配、双向判定（漏洞版该报/修复版该净）。
git 边界可注入，离线可测。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import evals.cve_replay as cve_replay
from evals.cve_replay import (
    CveCase,
    checkout_version,
    evaluate_replay,
    fetch_fix,
    load_cases,
    run_case,
)
from gloscope.models import Candidate, Finding, ScanReport, TriageResult, Verification


_CWE_BY_CATEGORY = {"sql_injection": "CWE-89", "ssrf": "CWE-918",
                    "path_traversal": "CWE-22"}


def _report_with(verdict: str | None, path: str, category: str) -> ScanReport:
    cwe = _CWE_BY_CATEGORY.get(category, "CWE-89")
    ver = Verification(verdict, cwe, [], "high") if verdict is not None else None
    return ScanReport(
        target="repo",
        findings=[Finding(
            candidate=Candidate("r.x", path, 10, 10, "s", "m", cwe, category),
            triage=TriageResult(True, "k"),
            verification=ver,
        )],
    )


CASE = CveCase(
    id="CVE-2020-0000", repo="https://github.com/x/y", fix_commit="abc123",
    category="sql_injection", file="app/db.py",
)


def test_evaluate_replay_both_directions():
    hit = evaluate_replay(
        CASE,
        parent=_report_with("confirmed", "app/db.py", "sql_injection"),
        fix=_report_with(None, "app/db.py", "sql_injection"),
    )
    assert hit.parent_hit is True
    assert hit.fix_clean is True

    miss = evaluate_replay(
        CASE,
        parent=_report_with("false_positive", "app/db.py", "sql_injection"),
        fix=_report_with("confirmed", "app/db.py", "sql_injection"),
    )
    assert miss.parent_hit is False
    assert miss.fix_clean is False  # 修复版仍报 → 不干净


def test_evaluate_replay_ignores_other_files_and_categories():
    r = evaluate_replay(
        CASE,
        parent=_report_with("confirmed", "other/file.py", "sql_injection"),
        fix=_report_with("confirmed", "app/db.py", "ssrf"),
    )
    assert r.parent_hit is False  # confirmed 不在 (file, category) 上 → 未命中
    assert r.fix_clean is True    # 别的类别/文件上的 confirmed 不影响本案例


def test_load_cases_fail_fast_on_bad_category(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text(json.dumps([
        {"id": "CVE-1", "repo": "https://github.com/a/b", "fix_commit": "f1",
         "category": "sql_injection", "file": "x.py"},
        {"id": "CVE-2", "repo": "https://github.com/a/c", "fix_commit": "f2",
         "category": "rce", "file": "y.py"},  # rce 不在八类注册表
    ]), encoding="utf-8")
    with pytest.raises(ValueError, match="CVE-2"):
        load_cases(p)


def test_fetch_fix_uses_depth2_and_returns_changed_files(tmp_path):
    calls = []

    def fake_git(argv, cwd):
        calls.append((list(argv), cwd))
        if argv[1] == "diff":
            return 0, "app/db.py\n", ""
        return 0, "", ""

    changed = fetch_fix(CASE.repo, CASE.fix_commit, tmp_path / "repo", git=fake_git)
    assert changed == ["app/db.py"]
    fetch = next(c for c in calls if c[0][1] == "fetch")
    assert fetch[0][2:4] == ["--depth", "2"]  # 深度 2 → fix + parent
    assert CASE.fix_commit in fetch[0]


def test_run_case_rust_scan_path_uses_gloscope_scan_not_cli_main(tmp_path, monkeypatch):
    """--rust-scan 分支必须走 run_rust_scan + 适配器，绝不能落到 legacy cli_main。"""
    calls: list[str] = []

    monkeypatch.setattr(cve_replay, "fetch_fix", lambda repo, commit, dest, git=None: [CASE.file])
    monkeypatch.setattr(cve_replay, "checkout_version", lambda dest, which, git=None: calls.append(which))

    def fake_cli_main(argv):
        raise AssertionError("rust_scan=True 不应调用 legacy cli_main")

    monkeypatch.setattr(cve_replay, "cli_main", fake_cli_main)

    def fake_run_rust_scan(gloscope_scan_path, repo_dir, gloscope_config, paths=None):
        calls.append(("run_rust_scan", paths))
        assert paths == [CASE.file]
        return 0

    monkeypatch.setattr(cve_replay, "run_rust_scan", fake_run_rust_scan)
    monkeypatch.setattr(
        cve_replay, "find_latest_findings_jsonl",
        lambda repo_dir, min_run_id=None: tmp_path / "findings.jsonl",
    )

    def fake_build_report(findings_path, target):
        return {"target": target, "created_at": "", "truncated": 0, "stats": {}, "findings": []}

    monkeypatch.setattr(cve_replay, "build_report", fake_build_report)

    result = run_case(
        CASE, config=None, out_dir=tmp_path / "out",
        rust_scan=True, gloscope_scan_path=Path("fake-gloscope-scan"),
    )
    assert result.error is None
    assert ("run_rust_scan", [CASE.file]) in calls
    assert calls.count("parent") == 1 and calls.count("fix") == 1


def test_checkout_version_selects_parent_or_fix(tmp_path):
    calls = []

    def fake_git(argv, cwd):
        calls.append(list(argv))
        return 0, "", ""

    checkout_version(tmp_path, "parent", git=fake_git)
    checkout_version(tmp_path, "fix", git=fake_git)
    assert calls == [
        ["git", "checkout", "-q", "-f", "FETCH_HEAD~1"],
        ["git", "checkout", "-q", "-f", "FETCH_HEAD"],
    ]
