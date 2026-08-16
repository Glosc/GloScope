"""Slice 6 — pipeline: 漏斗编排（最高接缝）。
semgrep/LLM/codex 三处外部边界全部注入假实现，不依赖真实工具链。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gloscope.models import Candidate, TriageResult, Verification
from gloscope.pipeline import Pipeline, PipelineOptions

CANDS = [
    Candidate("rule.sqli", "app.py", 12, 12, "run_query(dynamically_built_stmt)",
              "SQLi", "CWE-89", "sql_injection"),
    Candidate("rule.ssrf", "net.py", 8, 8, "perform_fetch(unvalidated_target)",
              "SSRF", "CWE-918", "ssrf"),
    Candidate("rule.traversal", "files.py", 27, 27, "open(joined_user_path)",
              "Path traversal", "CWE-22", "path_traversal"),
]


class FakeGenerator:
    def __init__(self, cands):
        self.cands = cands
        self.calls: list[Path] = []

    def run(self, target):
        self.calls.append(Path(target))
        return list(self.cands)


class FakeTriager:
    """按 check_id 决定 keep/drop；可注入抛异常行为。"""

    def __init__(self, drops=(), tokens=(50, 10), raise_on=None):
        self.drops, self.tokens = set(drops), tokens
        self.raise_on = raise_on
        self.seen = []

    def triage(self, cand):
        self.seen.append(cand)
        if self.raise_on and cand.check_id == self.raise_on:
            raise RuntimeError("triage exploded")
        return TriageResult(
            keep=cand.check_id not in self.drops,
            reason="fake", tokens_in=self.tokens[0], tokens_out=self.tokens[1],
        )


class FakeVerifier:
    def __init__(self, verdicts=None, error_on=None):
        self.verdicts = verdicts or {}
        self.error_on = error_on
        self.seen = []

    def verify(self, cand, target):
        self.seen.append((cand.check_id, Path(target)))
        if self.error_on and cand.check_id == self.error_on:
            raise RuntimeError("verify exploded")
        v = self.verdicts.get(cand.check_id, "confirmed")
        return Verification(verdict=v, cwe=cand.cwe or "", confidence="high", model="vm")


def build(gen=None, tri=None, ver=None, **opts):
    return Pipeline(
        generator=gen or FakeGenerator(CANDS),
        triager=tri,
        verifier=ver,
        options=PipelineOptions(**opts),
    )


def test_full_funnel_tracks_each_candidate():
    tri = FakeTriager(drops=["rule.traversal"])
    ver = FakeVerifier(verdicts={"rule.sqli": "confirmed", "rule.ssrf": "false_positive"})
    report = build(tri=tri, ver=ver).run(Path("target"))

    assert report.target == "target"
    assert len(report.findings) == 3
    by_rule = {f.candidate.check_id: f for f in report.findings}
    assert by_rule["rule.sqli"].status == "verified"
    assert by_rule["rule.sqli"].verification.verdict == "confirmed"
    assert by_rule["rule.ssrf"].status == "verified"
    assert by_rule["rule.traversal"].status == "dropped_at_triage"
    # verifier 只看 keep 的两个
    assert [c for c, _ in ver.seen] == ["rule.sqli", "rule.ssrf"]
    # verifier 拿到正确 target
    assert ver.seen[0][1] == Path("target")

    s = report.stats()
    assert (s.candidates, s.kept, s.dropped) == (3, 2, 1)
    assert (s.confirmed, s.false_positives, s.inconclusive) == (1, 1, 0)
    assert s.triage_tokens_in == 150  # 3 × 50
    # 分层耗时被记录
    assert s.semgrep_seconds >= 0 and s.triage_seconds >= 0 and s.verify_seconds >= 0


def test_skip_triage_sends_all_to_verifier():
    tri = FakeTriager(drops=["rule.sqli"])  # 即使会 drop 也不该被调用
    ver = FakeVerifier()
    report = build(tri=tri, ver=ver, skip_triage=True).run(Path("t"))
    assert tri.seen == []
    assert len(ver.seen) == 3
    assert all(f.status == "verified" for f in report.findings)


def test_skip_verify_leaves_kept_at_triage():
    tri = FakeTriager(drops=["rule.traversal"])
    report = build(tri=tri, ver=None, skip_verify=True).run(Path("t"))
    statuses = {f.candidate.check_id: f.status for f in report.findings}
    assert statuses == {"rule.sqli": "kept_at_triage",
                        "rule.ssrf": "kept_at_triage",
                        "rule.traversal": "dropped_at_triage"}


def test_skip_all_is_semgrep_only():
    report = build(tri=None, ver=None, skip_triage=True, skip_verify=True).run(Path("t"))
    assert all(f.status == "candidate" for f in report.findings)
    assert report.stats().tokens_total == 0


def test_max_candidates_truncates_and_records():
    report = build(tri=None, ver=None, skip_triage=True, skip_verify=True,
                   max_candidates=2).run(Path("t"))
    assert len(report.findings) == 2
    assert report.truncated == 1


def test_triage_exception_fails_open_per_candidate():
    tri = FakeTriager(raise_on="rule.ssrf")
    ver = FakeVerifier()
    report = build(tri=tri, ver=ver).run(Path("t"))
    by_rule = {f.candidate.check_id: f for f in report.findings}
    # 抛异常的候选保守保留（fail-open），并继续走验证
    assert by_rule["rule.ssrf"].triage.keep is True
    assert "triage exploded" in by_rule["rule.ssrf"].triage.reason
    assert by_rule["rule.ssrf"].status == "verified"
    assert len(ver.seen) == 3


def test_verify_exception_fails_open_to_inconclusive():
    ver = FakeVerifier(error_on="rule.sqli")
    report = build(tri=None, ver=ver, skip_triage=True).run(Path("t"))
    by_rule = {f.candidate.check_id: f for f in report.findings}
    v = by_rule["rule.sqli"].verification
    assert v.verdict == "inconclusive"
    assert v.error and "verify exploded" in v.error
    assert by_rule["rule.ssrf"].verification.verdict == "confirmed"


def test_missing_layers_without_skip_is_wiring_error():
    with pytest.raises(ValueError, match="triage"):
        build(tri=None, ver=None).run(Path("t"))


def test_verification_error_yields_error_status():
    from gloscope.models import Verification as V

    ver = FakeVerifier()
    ver.verify = lambda cand, target: V(
        verdict="inconclusive", cwe="", confidence="low", error="codex exec 超时")
    report = build(tri=None, ver=ver, skip_triage=True).run(Path("t"))
    f = report.findings[0]
    assert f.status == "error"
    assert f.is_inconclusive and not f.is_confirmed
