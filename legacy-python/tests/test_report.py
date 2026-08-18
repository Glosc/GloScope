"""Slice 5 — report: ScanReport → Markdown（人读）/ JSON（机器消费），含分层统计。
接缝：render_markdown / render_json 纯函数。
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
from gloscope.report import render_json, render_markdown

CAND_SINK = Candidate(
    check_id="python.flask.security.insecure-sql-query.insecure-sql-query",
    path="app.py", start_line=12, end_line=12,
    snippet="    run_query(dynamically_built_stmt)",
    message="非参数化 SQL 查询", cwe="CWE-89", category="sql_injection",
)
CAND_FP = Candidate(
    check_id="python.requests.security.requests-ssrf.requests-ssrf",
    path="services/fetch.py", start_line=8, end_line=8,
    snippet="    r = perform_fetch(unvalidated_target)",
    message="Possible SSRF", cwe="CWE-918", category="ssrf",
)
CAND_DROP = Candidate(
    check_id="python.lang.security.audit.path-traversal-open.path-traversal-open",
    path="tests/test_files.py", start_line=27, end_line=27,
    snippet="    with open(joined_user_path) as f:",
    message="Path traversal", cwe="CWE-22", category="path_traversal",
)


def build_report() -> ScanReport:
    return ScanReport(
        target="E:/targets/demo",
        created_at="2026-08-16T12:00:00",
        findings=[
            Finding(
                candidate=CAND_SINK,
                triage=TriageResult(True, "外部输入直达查询构造", "triage-model", 100, 20),
                verification=Verification(
                    verdict="confirmed", cwe="CWE-89",
                    taint_path=["app.py:5 - request.args.get 取参", "app.py:12 - sink"],
                    confidence="high", poc_idea="构造 id 参数观察查询结构",
                    explanation="污点可达且无净化", model="verify-model", tokens_in=500, tokens_out=80,
                ),
            ),
            Finding(
                candidate=CAND_FP,
                triage=TriageResult(True, "URL 有 host 白名单，疑似误报", "triage-model", 90, 15),
                verification=Verification(
                    verdict="false_positive", cwe="CWE-918", confidence="high",
                    explanation="目标 host 走白名单校验，不可控", model="verify-model",
                    tokens_in=400, tokens_out=60,
                ),
            ),
            Finding(
                candidate=CAND_DROP,
                triage=TriageResult(False, "测试文件中的固定路径", "triage-model", 80, 10),
            ),
        ],
    )


def test_markdown_contains_summary_and_all_layers():
    md = render_markdown(build_report())
    # 摘要统计
    assert "E:/targets/demo" in md
    assert "候选" in md and "3" in md
    assert "确认" in md and "1" in md
    assert "误报" in md
    # confirmed 详情：taint_path / confidence / poc / file:line 定位
    assert "app.py:5 - request.args.get 取参" in md
    assert "app.py:12" in md
    assert "high" in md
    assert "构造 id 参数观察查询结构" in md
    # 分诊理由与 drop 轨迹
    assert "测试文件中的固定路径" in md
    # token 成本与耗时摘要存在
    assert "token" in md.lower()


def test_markdown_orders_confirmed_before_others():
    md = render_markdown(build_report())
    assert md.index("confirmed") < md.index("false_positive")
    assert md.index("false_positive") < md.index("dropped")


def test_json_roundtrip_structure():
    data = json.loads(render_json(build_report()))
    assert data["target"] == "E:/targets/demo"
    assert len(data["findings"]) == 3
    first = data["findings"][0]
    assert first["candidate"]["path"] == "app.py"
    assert first["verification"]["verdict"] == "confirmed"
    assert first["triage"]["keep"] is True
    stats = data["stats"]
    assert stats["candidates"] == 3
    assert stats["confirmed"] == 1
    assert stats["false_positives"] == 1
    assert stats["dropped"] == 1
    assert stats["verify_tokens_in"] == 900


def test_empty_report_renders():
    md = render_markdown(ScanReport(target="t", created_at="now"))
    js = json.loads(render_json(ScanReport(target="t", created_at="now")))
    assert "0" in md
    assert js["findings"] == []


def test_inconclusive_error_surfaced():
    rep = ScanReport(
        target="t",
        findings=[Finding(
            candidate=CAND_SINK,
            triage=TriageResult(True, "需深查"),
            verification=Verification(
                verdict="inconclusive", cwe="", confidence="low",
                error="codex exec 超时", model="m"),
        )],
    )
    md = render_markdown(rep)
    assert "codex exec 超时" in md
    assert "inconclusive" in md


GOLDEN_MD = """\
# 寻幽 (GloScope) 漏洞审计报告

- 目标仓库：`E:/targets/demo`
- 生成时间：2026-08-16T12:00:00

## 漏斗摘要

| 层 | 结果 |
|---|---|
| 候选（semgrep） | 3 |
| 分诊保留 / 砍掉 | 2 / 1 |
| 确认 confirmed | 1 |
| 误报 false_positive | 1 |
| 存疑 inconclusive | 0（其中执行错误 0） |

- Token 成本：分诊 270/45（in/out），验证 900/140（in/out），合计 1355
- 耗时：semgrep 0.0s · 分诊 0.0s · 验证 0.0s

## 确认漏洞（confirmed）

### 1. [high] CWE-89 — app.py:12

- 规则：`python.flask.security.insecure-sql-query.insecure-sql-query`
- 代码：`run_query(dynamically_built_stmt)`
- 污点链：
  - `app.py:5 - request.args.get 取参`
  - `app.py:12 - sink`
- PoC 思路：构造 id 参数观察查询结构
- 依据：污点可达且无净化
- 分诊理由：外部输入直达查询构造

## 存疑（inconclusive）

（无）

## 验证为误报（false_positive）

- `services/fetch.py:8` — python.requests.security.requests-ssrf.requests-ssrf（CWE-918）：目标 host 走白名单校验，不可控

## 分诊砍掉（dropped at triage）

- `tests/test_files.py:27` — python.lang.security.audit.path-traversal-open.path-traversal-open：测试文件中的固定路径

## 未验证（跳过验证层）

（无）
"""


def test_markdown_golden():
    """golden：固定输入 → 人工审阅过的完整期望输出（结构变更必须显式更新此处）。"""
    assert render_markdown(build_report()) == GOLDEN_MD
