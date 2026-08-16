"""v2 — SARIF 2.1.0 输出：对接 GitHub Code Scanning / IDE 消费方。
接缝：render_sarif 纯函数。
"""

from __future__ import annotations

import json

from gloscope.models import (
    Candidate,
    Finding,
    ScanReport,
    TriageResult,
    Verification,
)
from gloscope.report import render_sarif


def build_report() -> ScanReport:
    return ScanReport(
        target="t",
        findings=[
            Finding(
                candidate=Candidate("rule.sqli", "app.py", 12, 12, "snip", "m",
                                    "CWE-89", "sql_injection"),
                triage=TriageResult(True, "k"),
                verification=Verification(
                    "confirmed", "CWE-89", ["app.py:5 - 取参", "app.py:12 - sink"],
                    "high", "poc-x", "污点可达", model="vm"),
            ),
            Finding(
                candidate=Candidate("rule.ssti", "introduction\\views.py", 995, 995,
                                    "s", "m", "CWE-94", "ssti"),
                triage=TriageResult(True, "k"),
                verification=Verification(
                    "inconclusive", "CWE-94", [], "low", "", "证据不足",
                    error="codex exec 超时", model="vm"),
            ),
            Finding(
                candidate=Candidate("rule.ssrf", "net.py", 8, 8, "s", "m",
                                    "CWE-918", "ssrf"),
                triage=TriageResult(True, "k"),
                verification=Verification(
                    "false_positive", "CWE-918", [], "high", "", "有白名单", model="vm"),
            ),
            Finding(
                candidate=Candidate("rule.trav", "files.py", 27, 27, "s", "m",
                                    "CWE-22", "path_traversal"),
                triage=TriageResult(False, "测试文件"),
            ),
        ],
    )


def test_sarif_skeleton_and_levels():
    sarif = json.loads(render_sarif(build_report()))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://json.schemastore.org/sarif-2.1.0")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "GloScope"
    results = sarif["runs"][0]["results"]
    # confirmed→error, inconclusive→warning；FP 与 dropped 不入
    assert [r["level"] for r in results] == ["error", "warning"]


def test_sarif_result_location_and_properties():
    sarif = json.loads(render_sarif(build_report()))
    first, second = sarif["runs"][0]["results"]
    assert first["ruleId"] == "rule.sqli"
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"  # 正斜杠相对路径
    assert loc["region"]["startLine"] == 12 and loc["region"]["endLine"] == 12
    props = first["properties"]
    assert props["verdict"] == "confirmed"
    assert props["cwe"] == "CWE-89"
    assert props["confidence"] == "high"
    assert props["taintPath"] == ["app.py:5 - 取参", "app.py:12 - sink"]
    assert props["pocIdea"] == "poc-x"
    # 反斜杠路径归一化（Windows semgrep 输出）
    assert second["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == \
        "introduction/views.py"
    assert second["properties"]["error"] == "codex exec 超时"


def test_sarif_empty_report_is_valid():
    sarif = json.loads(render_sarif(ScanReport(target="t")))
    assert sarif["runs"][0]["results"] == []
