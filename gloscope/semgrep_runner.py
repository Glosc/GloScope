"""第一层：包装 `semgrep --json`，把现成规则的结果解析为候选。"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable, TypeAlias

from gloscope.models import (
    CWE_TO_CATEGORY,
    Candidate,
    infer_category,
    infer_cwe,
    normalize_cwe,
)

# runner: (argv, cwd, timeout) -> (returncode, stdout, stderr)。可注入以便测试。
Runner: TypeAlias = Callable[[list[str], Path, float], "tuple[int, str, str]"]


class SemgrepError(RuntimeError):
    """semgrep 不可用、执行失败或输出不可解析。"""


def _real_runner(argv: list[str], cwd: Path, timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv, cwd=str(cwd), timeout=timeout, capture_output=True, text=True
    )
    return proc.returncode, proc.stdout, proc.stderr


class SemgrepCandidateGenerator:
    def __init__(
        self,
        semgrep_path: str = "semgrep",
        rules: str = "auto",
        timeout: float = 300.0,
        runner: Runner | None = None,
    ) -> None:
        self._semgrep = semgrep_path
        self._rules = rules
        self._timeout = timeout
        self._run = runner or _real_runner

    def run(self, target: Path) -> list[Candidate]:
        target = Path(target)
        # --no-git-ignore：审计需要覆盖保证，gitignored 文件同样要扫
        argv = [self._semgrep, "--json", "--no-git-ignore", "--config", self._rules, "."]
        try:
            returncode, stdout, stderr = self._run(argv, target, self._timeout)
        except FileNotFoundError as e:
            raise SemgrepError(
                "semgrep 未安装或不在 PATH：请先 `pip install semgrep`"
                "（或用 --semgrep-path 指定）"
            ) from e
        except subprocess.TimeoutExpired as e:
            raise SemgrepError(f"semgrep 超时（>{self._timeout:g}s）") from e
        if returncode != 0:
            raise SemgrepError(
                f"semgrep 退出码 {returncode}: {stderr.strip()[:500] or stdout.strip()[:500]}"
            )
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise SemgrepError(f"semgrep 输出不是合法 JSON: {e}") from e

        candidates: list[Candidate] = []
        for item in data.get("results", []):
            check_id = str(item.get("check_id", "unknown-rule"))
            metadata_cwe = normalize_cwe(
                item.get("extra", {}).get("metadata", {}).get("cwe")
            )
            # registry 规则的 metadata CWE 常见错挂（如 tainted-sql-string → CWE-704）；
            # 规则族能映射到已知类别时以规则族推断为准
            cwe = metadata_cwe
            if (cwe is None or cwe not in CWE_TO_CATEGORY) and (
                inferred := infer_cwe(check_id)
            ):
                cwe = inferred
            extra = item.get("extra", {})
            candidates.append(
                Candidate(
                    check_id=check_id,
                    path=str(item.get("path", "")),
                    start_line=int(item.get("start", {}).get("line", 0)),
                    end_line=int(item.get("end", {}).get("line", 0)),
                    snippet=str(extra.get("lines", "")),
                    message=str(extra.get("message", "")),
                    cwe=cwe,
                    category=infer_category(check_id, cwe),
                )
            )

        # django/flask 两套 registry 规则常同时命中同一 sink（同行或相邻行）→ 合并
        candidates.sort(key=lambda c: (c.path, c.start_line))
        deduped: list[Candidate] = []
        for c in candidates:
            is_dup = c.category != "unknown" and any(
                c.path == d.path
                and c.category == d.category
                and abs(c.start_line - d.start_line) <= 3
                for d in deduped
            )
            if not is_dup:
                deduped.append(c)
        return deduped
