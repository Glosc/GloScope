"""漏斗编排：候选生成 → 分诊 → 深度验证 → 报告数据。
三处外部边界（generator/triager/verifier）均为注入接口；单候选失败 fail-open 不中断扫描。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from gloscope.models import Finding, ScanReport, TriageResult, Verification
from gloscope.semgrep_runner import SemgrepCandidateGenerator
from gloscope.triage import OpenAITriageClient
from gloscope.verify import CodexVerifier


@dataclass
class PipelineOptions:
    skip_triage: bool = False
    skip_verify: bool = False
    max_candidates: int | None = None
    # 只让指定类别的候选进漏斗（如 v1 的三类目标）；None 表示不过滤
    categories: set[str] | None = None


class Pipeline:
    def __init__(
        self,
        generator: SemgrepCandidateGenerator,
        triager: OpenAITriageClient | None = None,
        verifier: CodexVerifier | None = None,
        options: PipelineOptions | None = None,
    ) -> None:
        self._generator = generator
        self._triager = triager
        self._verifier = verifier
        self._opts = options or PipelineOptions()
        if not self._opts.skip_triage and triager is None:
            raise ValueError("未提供 triage 层：请传入 triager 或显式 --skip-triage")
        if not self._opts.skip_verify and verifier is None:
            raise ValueError("未提供 verify 层：请传入 verifier 或显式 --skip-verify")

    def _run_stage(self, fn, fail_factory):
        """单候选单层执行：计时 + fail-open（异常转为保守结果，不中断扫描）。"""
        start = time.perf_counter()
        try:
            result = fn()
        except Exception as e:  # noqa: BLE001
            result = fail_factory(e)
        return result, time.perf_counter() - start

    def run(self, target: Path) -> ScanReport:
        target = Path(target)

        t0 = time.perf_counter()
        candidates = self._generator.run(target)
        semgrep_seconds = time.perf_counter() - t0

        truncated = 0
        if self._opts.categories is not None:
            before = len(candidates)
            candidates = [c for c in candidates if c.category in self._opts.categories]
            truncated += before - len(candidates)
        if self._opts.max_candidates is not None and len(candidates) > self._opts.max_candidates:
            truncated += len(candidates) - self._opts.max_candidates
            candidates = candidates[: self._opts.max_candidates]

        triage_seconds = 0.0
        verify_seconds = 0.0
        findings: list[Finding] = []

        for cand in candidates:
            finding = Finding(candidate=cand)

            if not self._opts.skip_triage:
                assert self._triager is not None
                triage, dt = self._run_stage(
                    lambda: self._triager.triage(cand),
                    lambda e: TriageResult(
                        keep=True, reason=f"triage 层异常（保守保留）: {e}"
                    ),
                )
                finding.triage = triage
                triage_seconds += dt

            if finding.is_kept and not self._opts.skip_verify:
                assert self._verifier is not None
                verification, dt = self._run_stage(
                    lambda: self._verifier.verify(cand, target),
                    lambda e: Verification(
                        verdict="inconclusive", cwe="", confidence="low",
                        error=f"verify 层异常: {e}",
                    ),
                )
                finding.verification = verification
                verify_seconds += dt

            findings.append(finding)

        report = ScanReport(
            target=str(target),
            findings=findings,
            truncated=truncated,
            semgrep_seconds=semgrep_seconds,
            triage_seconds=triage_seconds,
            verify_seconds=verify_seconds,
        )
        return report
