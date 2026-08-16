"""CVE 回放评测：checkout 真实 CVE 修复 commit 的漏洞版/修复版，双向验证漏斗。

判定口径（每案例）：
- parent_hit  —— 漏洞版（fix_commit~1）在案例文件上出现 confirmed（召回）
- fix_clean   —— 修复版（fix_commit）同文件无 confirmed（真实世界误报检验）

用法：
  python evals/cve_replay.py --config config.local.toml           # 全部案例
  python evals/cve_replay.py --config ... --only CVE-2021-35042   # 单案例
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeAlias

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gloscope.cli import main as cli_main  # noqa: E402
from gloscope.metrics import VULN_CATEGORIES, _finding_category  # noqa: E402
from gloscope.models import ScanReport  # noqa: E402
from gloscope.report import report_from_json  # noqa: E402

# git: (["git", <sub>, ...], cwd) -> (returncode, stdout, stderr)。可注入以便测试。
Git: TypeAlias = Callable[[list[str], Path], "tuple[int, str, str]"]


class ReplayError(RuntimeError):
    pass


@dataclass
class CveCase:
    id: str
    repo: str
    fix_commit: str
    category: str  # 八类之一
    file: str      # 修复触碰的关键文件（相对仓库根，正斜杠）


@dataclass
class ReplayResult:
    case: CveCase
    parent_hit: bool
    fix_clean: bool
    parent_confirmed: int = 0
    fix_confirmed: int = 0
    error: str | None = None

    @property
    def full_pass(self) -> bool:
        return self.parent_hit and self.fix_clean


def load_cases(path: Path | str) -> list[CveCase]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = []
    for i, raw in enumerate(data):
        category = str(raw.get("category", ""))
        if category not in VULN_CATEGORIES:
            raise ValueError(
                f"案例 {raw.get('id', i)} 类别非法: {category!r}"
                f"（支持: {sorted(VULN_CATEGORIES)}）"
            )
        cases.append(CveCase(
            id=str(raw["id"]), repo=str(raw["repo"]), fix_commit=str(raw["fix_commit"]),
            category=category, file=str(raw["file"]),
        ))
    return cases


def _real_git(argv: list[str], cwd: Path) -> tuple[int, str, str]:
    # argv 为固定形态参数列表（无 shell、无拼接），git 路径经 which 解析
    proc = subprocess.run(
        argv, cwd=str(cwd), capture_output=True, text=True, shell=False
    )
    return proc.returncode, proc.stdout, proc.stderr


def _run_git(argv: list[str], cwd: Path, git: Git) -> tuple[int, str, str]:
    returncode, out, err = git(argv, cwd)
    if returncode != 0:
        raise ReplayError(f"git {argv[1]} 失败（退出码 {returncode}）: {err.strip()[:300]}")
    return returncode, out, err


def fetch_fix(repo_url: str, fix_commit: str, dest: Path, git: Git = _real_git) -> list[str]:
    """浅取 fix commit 及其父（--depth 2），返回两版差异文件清单。"""
    dest.mkdir(parents=True, exist_ok=True)
    _run_git(["git", "init", "-q"], dest, git)
    _run_git(["git", "remote", "add", "origin", repo_url], dest, git)
    _run_git(["git", "fetch", "--depth", "2", "-q", "origin", fix_commit], dest, git)
    _, out, _ = _run_git(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", "FETCH_HEAD~1", "FETCH_HEAD"],
        dest, git,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def checkout_version(dest: Path, which: str, git: Git = _real_git) -> None:
    """which: 'parent'（漏洞版 FETCH_HEAD~1）或 'fix'（修复版 FETCH_HEAD）。"""
    if which not in ("parent", "fix"):
        raise ValueError(f"which 必须是 parent/fix: {which!r}")
    ref = "FETCH_HEAD~1" if which == "parent" else "FETCH_HEAD"
    _run_git(["git", "checkout", "-q", "-f", ref], dest, git)


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _confirmed_at(report: ScanReport, file: str, category: str) -> int:
    """案例命中口径与 metrics 一致：(file, category)，类别以验证层纠正后的为准。"""
    return sum(
        1 for f in report.findings
        if f.is_confirmed
        and _norm(f.candidate.path) == file
        and _finding_category(f) == category
    )


def evaluate_replay(case: CveCase, parent: ScanReport, fix: ScanReport) -> ReplayResult:
    parent_confirmed = _confirmed_at(parent, case.file, case.category)
    fix_confirmed = _confirmed_at(fix, case.file, case.category)
    return ReplayResult(
        case=case,
        parent_hit=parent_confirmed > 0,
        fix_clean=fix_confirmed == 0,
        parent_confirmed=parent_confirmed,
        fix_confirmed=fix_confirmed,
    )


def run_case(case: CveCase, config: str, out_dir: Path,
             semgrep_path: str = "semgrep") -> ReplayResult:
    """装配一次双向回放：parent 扫描 → fix 扫描 → 判定。"""
    workdir = Path(tempfile.mkdtemp(prefix="gloscope-cve-"))
    repo_dir = workdir / "repo"
    try:
        changed = fetch_fix(case.repo, case.fix_commit, repo_dir)
        if case.file not in changed:
            return ReplayResult(
                case, False, False,
                error=f"案例标注文件 {case.file} 不在 fix diff 中（实际: {changed[:5]}）",
            )
        results_dir = out_dir / case.id
        reports: dict[str, ScanReport] = {}
        for which in ("parent", "fix"):
            checkout_version(repo_dir, which)
            case_dir = results_dir / which
            rc = cli_main([
                "scan", str(repo_dir),
                "--config", config,
                "--categories", case.category,
                "--paths", case.file,
                "--semgrep-path", semgrep_path,
                "--output-dir", str(case_dir),
            ])
            if rc != 0:
                return ReplayResult(case, False, False, error=f"{which} 扫描失败（退出码 {rc}）")
            reports[which] = report_from_json(
                (case_dir / "report.json").read_text(encoding="utf-8")
            )
        return evaluate_replay(case, reports["parent"], reports["fix"])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def format_summary(results: list[ReplayResult]) -> str:
    lines = [
        f"CVE 回放：{sum(r.full_pass for r in results)}/{len(results)} 全通过",
        "",
        "| CVE | 类别 | 漏洞版命中 | 修复版干净 | confirmed(parent→fix) | 备注 |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        mark_p = "✅" if r.parent_hit else "❌"
        mark_f = "✅" if r.fix_clean else "❌"
        lines.append(
            f"| {r.case.id} | {r.case.category} | {mark_p} | {mark_f} "
            f"| {r.parent_confirmed}→{r.fix_confirmed} | {r.error or ''} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cve_replay", description="CVE 修复 commit 回放评测")
    parser.add_argument("--cases", default=str(REPO_ROOT / "evals" / "cve_cases.json"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--only", help="只跑指定 CVE id")
    parser.add_argument("--out", default=str(REPO_ROOT / "evals" / "results" / "cve"))
    parser.add_argument("--semgrep-path", default="semgrep")
    args = parser.parse_args(argv)

    cases = [c for c in load_cases(args.cases) if not args.only or c.id == args.only]
    if not cases:
        print("没有可运行的案例", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    results = []
    for case in cases:
        print(f"[{case.id}] 回放中 …", flush=True)
        r = run_case(case, args.config, out_dir, semgrep_path=args.semgrep_path)
        results.append(r)
        status = f"parent_hit={r.parent_hit} fix_clean={r.fix_clean}"
        print(f"[{case.id}] {status}" + (f" error={r.error}" if r.error else ""), flush=True)

    summary = format_summary(results)
    print()
    print(summary)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
