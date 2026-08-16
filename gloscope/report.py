"""第四层：报告渲染。ScanReport → Markdown（人读）/ JSON（机器消费）。"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from gloscope import __version__
from gloscope.models import (
    Candidate,
    Finding,
    ScanReport,
    TriageResult,
    Verification,
    asdict_jsonable,
)

_ORDER = {"high": 0, "medium": 1, "low": 2}


def _section_confirmed(f: Finding, idx: int) -> list[str]:
    c, v = f.candidate, f.verification
    assert v is not None
    lines = [
        f"### {idx}. [{v.confidence}] {v.cwe or c.cwe or 'CWE-?'} — {c.location}",
        "",
        f"- 规则：`{c.check_id}`",
        f"- 代码：`{c.snippet.strip()}`",
    ]
    if v.taint_path:
        lines.append("- 污点链：")
        lines.extend(f"  - `{step}`" for step in v.taint_path)
    if v.poc_idea:
        lines.append(f"- PoC 思路：{v.poc_idea}")
    if v.explanation:
        lines.append(f"- 依据：{v.explanation}")
    if f.triage and f.triage.reason:
        lines.append(f"- 分诊理由：{f.triage.reason}")
    if v.error:
        lines.append(f"- ⚠️ 验证层错误：{v.error}")
    return lines


def _section_other(title: str, findings: list[Finding], with_details: bool) -> list[str]:
    if not findings:
        return [f"## {title}", "", "（无）", ""]
    lines = [f"## {title}", ""]
    for f in findings:
        c, v = f.candidate, f.verification
        head = f"- `{c.location}` — {c.check_id}"
        if v is not None:
            extra = f"（{v.cwe or 'CWE-?'}）" if v.cwe else ""
            if v.error:
                extra += f" ⚠️ {v.error}"
            elif v.explanation:
                extra += f"：{v.explanation}"
            head += extra
        elif f.triage is not None and f.triage.reason:
            head += f"：{f.triage.reason}"
        lines.append(head)
        if with_details and v is not None and v.taint_path:
            lines.extend(f"  - `{step}`" for step in v.taint_path)
    lines.append("")
    return lines


def render_markdown(report: ScanReport) -> str:
    s = report.stats()
    created = report.created_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    confirmed = sorted(
        (f for f in report.findings if f.is_confirmed),
        key=lambda f: _ORDER.get(f.verification.confidence if f.verification else "low", 9),
    )
    inconclusive = [f for f in report.findings if f.is_inconclusive]
    false_pos = [f for f in report.findings if f.is_false_positive]
    dropped = [f for f in report.findings if f.status == "dropped_at_triage"]
    unverified = [f for f in report.findings if f.status in ("candidate", "kept_at_triage")]

    lines = [
        "# 寻幽 (GloScope) 漏洞审计报告",
        "",
        f"- 目标仓库：`{report.target}`",
        f"- 生成时间：{created}",
        "",
        "## 漏斗摘要",
        "",
        "| 层 | 结果 |",
        "|---|---|",
        f"| 候选（semgrep） | {s.candidates} |",
        f"| 分诊保留 / 砍掉 | {s.kept} / {s.dropped} |",
        f"| 确认 confirmed | {s.confirmed} |",
        f"| 误报 false_positive | {s.false_positives} |",
        f"| 存疑 inconclusive | {s.inconclusive}（其中执行错误 {s.errors}） |",
        "",
        f"- Token 成本：分诊 {s.triage_tokens_in}/{s.triage_tokens_out}（in/out），"
        f"验证 {s.verify_tokens_in}/{s.verify_tokens_out}（in/out），合计 {s.tokens_total}",
        f"- 耗时：semgrep {s.semgrep_seconds:.1f}s · 分诊 {s.triage_seconds:.1f}s · 验证 {s.verify_seconds:.1f}s",
    ]
    if report.truncated:
        lines.append(f"- ⚠️ 受 --max-candidates 限制，截断候选 {report.truncated} 个")
    lines.append("")

    if confirmed:
        lines.append("## 确认漏洞（confirmed）")
        lines.append("")
        for i, f in enumerate(confirmed, 1):
            lines.extend(_section_confirmed(f, i))
        lines.append("")
    lines.extend(_section_other("存疑（inconclusive）", inconclusive, with_details=True))
    lines.extend(_section_other("验证为误报（false_positive）", false_pos, with_details=False))
    lines.extend(_section_other("分诊砍掉（dropped at triage）", dropped, with_details=False))
    lines.extend(_section_other("未验证（跳过验证层）", unverified, with_details=False))
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: ScanReport) -> str:
    s = report.stats()
    payload = {
        "target": report.target,
        "created_at": report.created_at,
        "truncated": report.truncated,
        "stats": {
            "candidates": s.candidates,
            "kept": s.kept,
            "dropped": s.dropped,
            "confirmed": s.confirmed,
            "false_positives": s.false_positives,
            "inconclusive": s.inconclusive,
            "errors": s.errors,
            "triage_tokens_in": s.triage_tokens_in,
            "triage_tokens_out": s.triage_tokens_out,
            "verify_tokens_in": s.verify_tokens_in,
            "verify_tokens_out": s.verify_tokens_out,
            "tokens_total": s.tokens_total,
            "semgrep_seconds": s.semgrep_seconds,
            "triage_seconds": s.triage_seconds,
            "verify_seconds": s.verify_seconds,
        },
        "findings": [asdict_jsonable(f) for f in report.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_sarif(report: ScanReport) -> str:
    """SARIF 2.1.0 最小可用子集：confirmed→error、inconclusive→warning；
    false_positive/dropped 非 actionable 不入；验证依据进 result.properties。
    """
    results = []
    for f in report.findings:
        if not (f.is_confirmed or f.is_inconclusive):
            continue
        v = f.verification
        assert v is not None
        results.append(
            {
                "ruleId": f.candidate.check_id,
                "level": "error" if f.is_confirmed else "warning",
                "message": {"text": v.explanation or f.candidate.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.candidate.path.replace("\\", "/")
                            },
                            "region": {
                                "startLine": f.candidate.start_line,
                                "endLine": f.candidate.end_line,
                            },
                        }
                    }
                ],
                "properties": {
                    "verdict": v.verdict,
                    "cwe": v.cwe or f.candidate.cwe or "",
                    "confidence": v.confidence,
                    "taintPath": v.taint_path,
                    "pocIdea": v.poc_idea,
                    **({"error": v.error} if v.error else {}),
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "GloScope", "version": __version__}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def report_from_json(text: str) -> ScanReport:
    """render_json 的逆：eval 子命令从报告 JSON 离线回放评测。"""
    data = json.loads(text)
    findings: list[Finding] = []
    for f in data.get("findings", []):
        c = f["candidate"]
        cand = Candidate(
            check_id=c["check_id"], path=c["path"],
            start_line=c["start_line"], end_line=c["end_line"],
            snippet=c.get("snippet", ""), message=c.get("message", ""),
            cwe=c.get("cwe"), category=c.get("category", "unknown"),
            source=c.get("source", "semgrep"),
        )
        tri = None
        if f.get("triage"):
            t = f["triage"]
            tri = TriageResult(
                keep=t["keep"], reason=t.get("reason", ""), model=t.get("model", ""),
                tokens_in=t.get("tokens_in", 0), tokens_out=t.get("tokens_out", 0),
            )
        ver = None
        if f.get("verification"):
            v = f["verification"]
            ver = Verification(
                verdict=v["verdict"], cwe=v.get("cwe", ""),
                taint_path=list(v.get("taint_path", [])),
                confidence=v.get("confidence", "low"),
                poc_idea=v.get("poc_idea", ""), explanation=v.get("explanation", ""),
                poc_method=v.get("poc_method", ""), poc_path=v.get("poc_path", ""),
                poc_query=v.get("poc_query", ""), poc_body=v.get("poc_body", ""),
                poc_signal=v.get("poc_signal", ""),
                error=v.get("error"), model=v.get("model", ""),
                tokens_in=v.get("tokens_in", 0), tokens_out=v.get("tokens_out", 0),
            )
        findings.append(Finding(candidate=cand, triage=tri, verification=ver))
    stats = data.get("stats", {})
    return ScanReport(
        target=data.get("target", ""), findings=findings,
        truncated=data.get("truncated", 0), created_at=data.get("created_at", ""),
        semgrep_seconds=float(stats.get("semgrep_seconds", 0)),
        triage_seconds=float(stats.get("triage_seconds", 0)),
        verify_seconds=float(stats.get("verify_seconds", 0)),
    )
