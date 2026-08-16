"""评测：固定靶场 + ground truth → 四指标（召回率、误报数、token 成本、耗时）+ 漏斗分层对比。
离线计算：一份完整扫描报告即可回放出 semgrep / +triage / full 三行指标。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from gloscope.models import CWE_TO_CATEGORY, VULN_CATEGORIES, Finding, ScanReport

KNOWN_CATEGORIES = set(VULN_CATEGORIES)


@dataclass
class GroundTruthItem:
    path: str
    category: str
    line: int


@dataclass
class FunnelRow:
    name: str  # "semgrep" | "+triage" | "full"
    tp: int
    fn: int
    recall: float
    fp: int
    tokens: int
    seconds: float


@dataclass
class EvalResult:
    ground_truth_size: int
    rows: list[FunnelRow]


def load_ground_truth(path: Path | str) -> list[GroundTruthItem]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items: list[GroundTruthItem] = []
    for i, raw in enumerate(data):
        category = str(raw.get("category", ""))
        if category not in KNOWN_CATEGORIES:
            raise ValueError(
                f"ground truth 第 {i} 项类别非法: {category!r}（支持: {sorted(KNOWN_CATEGORIES)}）"
            )
        items.append(
            GroundTruthItem(
                path=str(raw["path"]), category=category, line=int(raw.get("line", 0))
            )
        )
    return items


def _finding_category(f: Finding) -> str:
    """匹配类别：验证层纠正过的 CWE 优先，回退候选类别。unknown 永不匹配。"""
    if f.verification is not None and f.verification.cwe:
        return CWE_TO_CATEGORY.get(f.verification.cwe, f.candidate.category)
    return f.candidate.category


def _norm(path: str) -> str:
    """Windows 上 semgrep 输出反斜杠路径，GT 统一正斜杠。"""
    return path.replace("\\", "/")


def _match(findings: list[Finding], gt: GroundTruthItem) -> bool:
    return any(
        _norm(f.candidate.path) == gt.path and _finding_category(f) == gt.category
        for f in findings
    )


def evaluate(report: ScanReport, ground_truth: list[GroundTruthItem]) -> EvalResult:
    s = report.stats()
    stages = [
        ("semgrep", report.findings, 0, s.semgrep_seconds),
        ("+triage", [f for f in report.findings if f.is_kept],
         s.triage_tokens_in + s.triage_tokens_out,
         s.semgrep_seconds + s.triage_seconds),
        ("full", [f for f in report.findings if f.is_confirmed],
         s.tokens_total, s.semgrep_seconds + s.triage_seconds + s.verify_seconds),
    ]
    rows: list[FunnelRow] = []
    gt_set = {(g.path, g.category) for g in ground_truth}
    for name, hits, tokens, seconds in stages:
        tp = sum(1 for g in ground_truth if _match(hits, g))
        fp = sum(
            1 for f in hits if (_norm(f.candidate.path), _finding_category(f)) not in gt_set
        )
        recall = tp / len(ground_truth) if ground_truth else 0.0
        rows.append(
            FunnelRow(name=name, tp=tp, fn=len(ground_truth) - tp, recall=recall,
                      fp=fp, tokens=tokens, seconds=seconds)
        )
    return EvalResult(ground_truth_size=len(ground_truth), rows=rows)


def format_table(result: EvalResult) -> str:
    lines = [
        f"ground truth: {result.ground_truth_size} 项",
        "",
        "| 漏斗层 | 召回率 | 误报数 | token 成本 | 耗时(s) |",
        "|---|---|---|---|---|",
    ]
    for r in result.rows:
        lines.append(
            f"| {r.name} | {r.recall:.3f} | {r.fp} | {r.tokens} | {r.seconds:.1f} |"
        )
    return "\n".join(lines)
