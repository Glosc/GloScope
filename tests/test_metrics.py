"""Slice 7 — metrics: 固定靶场上的四指标评测（召回率、误报数、token 成本、耗时）+ 漏斗分层对比。
接缝：evaluate(report, ground_truth) / load_ground_truth。离线：从一份扫描报告即可计算。
"""

from __future__ import annotations

import json

import pytest

from gloscope.metrics import (
    EvalResult,
    FunnelRow,
    GroundTruthItem,
    evaluate,
    format_table,
    load_ground_truth,
)
from gloscope.models import Candidate, Finding, ScanReport, TriageResult, Verification

def cand(rule, path, cat):
    return Candidate(rule, path, 10, 10, "snip", "msg", {
        "sql_injection": "CWE-89", "ssrf": "CWE-918",
        "path_traversal": "CWE-22", "unknown": None}[cat], cat)


def build_report() -> ScanReport:
    """GT: app.py sqli / net.py ssrf / files.py traversal。
    漏斗: sqli+ssrf confirmed；traversal 被 triage drop；
    另有 misc.py unknown 类候选 confirmed（GT 外 → 三层都是误报）。
    """
    return ScanReport(
        target="tiny_app",
        findings=[
            Finding(
                candidate=cand("r1", "app.py", "sql_injection"),
                triage=TriageResult(True, "k", tokens_in=100, tokens_out=10),
                verification=Verification("confirmed", "CWE-89", ["app.py:10 - sink"],
                                          "high", "", "", tokens_in=500, tokens_out=50),
            ),
            Finding(
                candidate=cand("r2", "net.py", "ssrf"),
                triage=TriageResult(True, "k", tokens_in=100, tokens_out=10),
                verification=Verification("confirmed", "CWE-918", ["net.py:10 - sink"],
                                          "medium", "", "", tokens_in=400, tokens_out=40),
            ),
            Finding(
                candidate=cand("r3", "files.py", "path_traversal"),
                triage=TriageResult(False, "测试文件", tokens_in=100, tokens_out=10),
            ),
            Finding(
                candidate=cand("r4", "misc.py", "unknown"),
                triage=TriageResult(True, "k", tokens_in=100, tokens_out=10),
                verification=Verification("confirmed", "", [], "low", "", "",
                                          tokens_in=300, tokens_out=30),
            ),
        ],
        semgrep_seconds=2.0,
        triage_seconds=3.0,
        verify_seconds=30.0,
    )


GT = [
    GroundTruthItem(path="app.py", category="sql_injection", line=12),
    GroundTruthItem(path="net.py", category="ssrf", line=8),
    GroundTruthItem(path="files.py", category="path_traversal", line=27),
]


def test_funnel_rows_recall_fp_tokens_seconds():
    r = evaluate(build_report(), GT)
    assert r.ground_truth_size == 3
    by_name = {row.name: row for row in r.rows}
    assert set(by_name) == {"semgrep", "+triage", "full"}

    sem = by_name["semgrep"]
    assert (sem.tp, sem.fn) == (3, 0)
    assert sem.recall == 1.0
    assert sem.fp == 1  # misc.py unknown 候选
    assert sem.tokens == 0 and sem.seconds == 2.0  # 到该层为止的累计成本

    tri = by_name["+triage"]
    assert (tri.tp, tri.fn) == (2, 1)  # traversal 被分诊砍掉
    assert tri.recall == pytest.approx(2 / 3)
    assert tri.fp == 1
    assert tri.tokens == 440  # 分诊层 4×(100+10)
    assert tri.seconds == 5.0

    full = by_name["full"]
    assert (full.tp, full.fn, full.fp) == (2, 1, 1)
    assert full.recall == pytest.approx(2 / 3)
    assert full.tokens == 440 + 1320  # + 验证层 3×(in+out)
    assert full.seconds == 35.0


def test_unknown_category_never_matches():
    # 候选类别推断失败（unknown）时，即使路径相同也不命中任何 ground truth
    gt = [GroundTruthItem(path="misc.py", category="ssrf", line=1)]
    r = evaluate(build_report(), gt)
    assert r.rows[0].tp == 0


def test_path_matching_normalizes_separators():
    """pygoat 实测：Windows 上 semgrep 输出反斜杠路径，GT 用正斜杠 → 必须归一化。"""
    rep = ScanReport(target="t", findings=[Finding(
        candidate=Candidate("r.ssrf", r"introduction\views.py", 963, 963,
                            "s", "m", "CWE-918", "ssrf"),
    )])
    gt = [GroundTruthItem("introduction/views.py", "ssrf", 963)]
    assert evaluate(rep, gt).rows[0].tp == 1


def test_category_match_prefers_verification_cwe():
    # semgrep 报 sqli，验证层纠正为 CWE-918(ssrf)：full 层按 ssrf 匹配
    rep = ScanReport(target="t", findings=[Finding(
        candidate=cand("r1", "app.py", "sql_injection"),
        triage=TriageResult(True, "k"),
        verification=Verification("confirmed", "CWE-918", [], "high"),
    )])
    gt_ssrf = [GroundTruthItem("app.py", "ssrf", 1)]
    gt_sqli = [GroundTruthItem("app.py", "sql_injection", 1)]
    assert evaluate(rep, gt_ssrf).rows[2].tp == 1
    assert evaluate(rep, gt_sqli).rows[2].tp == 0  # full 层不再按 sql_injection 匹配


def test_load_ground_truth_json(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text(json.dumps([
        {"path": "app.py", "category": "sql_injection", "line": 12},
        {"path": "net.py", "category": "ssrf", "line": 8},
    ]), encoding="utf-8")
    items = load_ground_truth(p)
    assert items[0] == GroundTruthItem("app.py", "sql_injection", 12)


def test_load_ground_truth_rejects_bad_category(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text(json.dumps([{"path": "a.py", "category": "rce", "line": 1}]), encoding="utf-8")
    with pytest.raises(ValueError, match="rce"):
        load_ground_truth(p)


def test_format_table_has_four_metrics():
    text = format_table(evaluate(build_report(), GT))
    assert "召回率" in text and "误报" in text and "token" in text.lower() and "耗时" in text
    assert "semgrep" in text and "full" in text
    assert "1.000" in text  # semgrep 行召回
