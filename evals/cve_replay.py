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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeAlias

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "legacy-python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gloscope.cli import main as cli_main  # noqa: E402
from gloscope.metrics import VULN_CATEGORIES, _finding_category  # noqa: E402
from gloscope.models import ScanReport  # noqa: E402
from gloscope.report import report_from_json  # noqa: E402

from rust_report_adapter import build_report  # noqa: E402
from run_eval import find_latest_findings_jsonl, resolve_gloscope_scan_path, run_rust_scan  # noqa: E402

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
    note: str = ""


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
            category=category, file=str(raw["file"]), note=str(raw.get("note", "")),
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


def _scan_legacy(repo_dir: Path, case: CveCase, config: str, case_dir: Path,
                  semgrep_path: str) -> ScanReport | None:
    rc = cli_main([
        "scan", str(repo_dir),
        "--config", config,
        "--categories", case.category,
        "--paths", case.file,
        "--semgrep-path", semgrep_path,
        "--output-dir", str(case_dir),
    ])
    if rc != 0:
        return None
    return report_from_json((case_dir / "report.json").read_text(encoding="utf-8"))


def _scan_rust(repo_dir: Path, case: CveCase, case_dir: Path,
                gloscope_scan_path: Path, gloscope_config: str | None) -> ScanReport | None:
    """新 Rust/Tauri 栈路径：headless gloscope-scan 只扫 case.file，跑完用适配器转成
    legacy schema。不移植 --categories 过滤——evaluate_replay 本来就按 (file, category)
    过滤，多扫的类别不影响命中判定，只是多花一点 token。

    同一个 repo_dir 会被 parent/fix 两个阶段先后扫描两次；如果 fix 阶段本身零候选
    通过 submit_verdict（不会新建 run 目录），`find_latest_findings_jsonl` 若不加
    过滤会误把 parent 阶段留下的旧目录当成本次结果——扫描前先记一个时间戳下限，
    排除早于本次扫描的 run 目录。"""
    min_run_id = str(int(time.time() * 1000))
    rc = run_rust_scan(gloscope_scan_path, repo_dir, gloscope_config, paths=[case.file])
    if rc != 0:
        return None
    findings_path = find_latest_findings_jsonl(repo_dir, min_run_id=min_run_id)
    report_dict = build_report(findings_path, str(repo_dir))
    case_dir.mkdir(parents=True, exist_ok=True)
    report_json_path = case_dir / "report.json"
    report_json_path.write_text(json.dumps(report_dict, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_from_json(report_json_path.read_text(encoding="utf-8"))


def run_case(case: CveCase, config: str, out_dir: Path,
             semgrep_path: str = "semgrep",
             rust_scan: bool = False,
             gloscope_scan_path: Path | None = None,
             gloscope_config: str | None = None) -> ReplayResult:
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
            if rust_scan:
                assert gloscope_scan_path is not None
                report = _scan_rust(repo_dir, case, case_dir, gloscope_scan_path, gloscope_config)
            else:
                report = _scan_legacy(repo_dir, case, config, case_dir, semgrep_path)
            if report is None:
                return ReplayResult(case, False, False, error=f"{which} 扫描失败")
            reports[which] = report
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
        note = r.error or r.case.note
        lines.append(
            f"| {r.case.id} | {r.case.category} | {mark_p} | {mark_f} "
            f"| {r.parent_confirmed}→{r.fix_confirmed} | {note} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cve_replay", description="CVE 修复 commit 回放评测")
    parser.add_argument("--cases", default=str(REPO_ROOT / "evals" / "cve_cases.json"))
    parser.add_argument("--config", help="legacy Python 栈 TOML 配置路径（--rust-scan 时不需要）")
    parser.add_argument("--rust-scan", action="store_true",
                        help="在线（新 Rust/Tauri 栈）：headless gloscope-scan + 适配器，替代 legacy cli_main")
    parser.add_argument("--gloscope-scan-path", help="rust-scan 模式：gloscope-scan 二进制路径")
    parser.add_argument("--gloscope-config", help="rust-scan 模式：GLOSCOPE_HOME 覆盖（可选）")
    parser.add_argument("--only", help="只跑指定 CVE id")
    parser.add_argument("--out", default=str(REPO_ROOT / "evals" / "results" / "cve"))
    parser.add_argument("--semgrep-path", default="semgrep")
    args = parser.parse_args(argv)

    if args.rust_scan:
        gloscope_scan_path = resolve_gloscope_scan_path(args.gloscope_scan_path)
    else:
        gloscope_scan_path = None
        if not args.config:
            print("legacy 栈模式需要 --config", file=sys.stderr)
            return 1

    cases = [c for c in load_cases(args.cases) if not args.only or c.id == args.only]
    if not cases:
        print("没有可运行的案例", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    results = []
    for case in cases:
        print(f"[{case.id}] 回放中 …", flush=True)
        r = run_case(
            case, args.config, out_dir, semgrep_path=args.semgrep_path,
            rust_scan=args.rust_scan, gloscope_scan_path=gloscope_scan_path,
            gloscope_config=args.gloscope_config,
        )
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
