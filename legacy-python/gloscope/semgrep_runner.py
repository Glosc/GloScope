"""第一层：包装 `semgrep --json`，把现成规则的结果解析为候选。"""

from __future__ import annotations

import json
import shutil
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

# 自写盲区补充规则（与 --config auto 并联默认启用）：CVE 回放实测 auto 在
# 实例属性路径 / str() 拼接路径两类真实穿越形态上零候选
BUNDLED_RULES = Path(__file__).resolve().parent / "rules" / "blindspots.yml"

# runner: (argv, cwd, timeout) -> (returncode, stdout, stderr)。可注入以便测试。
Runner: TypeAlias = Callable[[list[str], Path, float], "tuple[int, str, str]"]


class SemgrepError(RuntimeError):
    """semgrep 不可用、执行失败或输出不可解析。"""


def _real_runner(argv: list[str], cwd: Path, timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv, cwd=str(cwd), timeout=timeout, capture_output=True, text=True
    )
    return proc.returncode, proc.stdout, proc.stderr


def _git_changed_files(target: Path, base: str) -> list[str]:
    """diff-aware 增量扫描：base...HEAD 间新增/复制/修改/重命名的文件（相对 target 根）。"""
    git = shutil.which("git") or "git"
    proc = subprocess.run(
        [git, "-C", str(target), "diff", "--name-only", "--diff-filter=ACMR", base],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"获取 diff 失败（base={base!r}）: {proc.stderr.strip()[:300]}"
        )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


class SemgrepCandidateGenerator:
    def __init__(
        self,
        semgrep_path: str = "semgrep",
        rules: str = "auto",
        timeout: float = 300.0,
        runner: Runner | None = None,
        diff_base: str | None = None,
        paths: list[str] | None = None,
    ) -> None:
        if diff_base is not None and paths:
            raise ValueError("paths 与 diff_base 互斥：显式文件清单与增量模式二选一")
        # Windows 下 npm/venv 工具多为 .cmd/.exe shim，subprocess 不解析裸名 → which 预解析
        self._semgrep = shutil.which(semgrep_path) or semgrep_path
        self._rules = rules
        self._timeout = timeout
        self._diff_base = diff_base
        self._paths = paths
        self._run = runner or _real_runner

    @staticmethod
    def _read_snippet(target: Path, rel_path: str, start: int, end: int) -> str | None:
        """extra.lines 实测不可靠（可能返回无关固定文本）；以源文件为准。"""
        try:
            lines = (target / rel_path).read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            return None
        if 1 <= start <= end <= len(lines):
            return "\n".join(lines[start - 1 : end])
        return None

    def run(self, target: Path) -> list[Candidate]:
        target = Path(target)
        # --no-git-ignore：审计需要覆盖保证，gitignored 文件同样要扫
        argv = [self._semgrep, "--json", "--no-git-ignore",
                "--config", self._rules, "--config", str(BUNDLED_RULES)]
        if self._paths is not None:
            argv += self._paths
        else:
            # 只扫 Python：目标定位 Python Web 项目，semgrep 规则族对 vendored
            # JS/HTML 资源误报极高（dogfood 实测 108 候选中 ~70 来自前端静态库）。
            # paths 模式不覆盖——用户显式指定的文件清单即意图。
            argv += ["--include", "*.py"]
            if self._diff_base is not None:
                # 显式文件清单与 --include 的组合语义不可靠，改为 Python 侧过滤
                try:
                    changed = _git_changed_files(target, self._diff_base)
                except Exception as e:  # noqa: BLE001 — 增量信息拿不到就不该盲目全仓扫
                    raise SemgrepError(
                        f"--diff-base 增量扫描失败: {e}（如需全仓扫描请去掉 --diff-base）"
                    ) from e
                argv += [f for f in changed if f.endswith(".py")]
            else:
                argv.append(".")
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
            start_line = int(item.get("start", {}).get("line", 0))
            end_line = int(item.get("end", {}).get("line", 0))
            path = str(item.get("path", ""))
            snippet = self._read_snippet(target, path, start_line, end_line)
            if snippet is None:
                snippet = str(extra.get("lines", ""))
            candidates.append(
                Candidate(
                    check_id=check_id,
                    path=path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=snippet,
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
