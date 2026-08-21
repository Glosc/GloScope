"""评测脚本：固定靶场 → 四指标（召回率、误报数、token 成本、耗时）+ 漏斗分层对比。

用法：
  # 离线：对一份 scan 报告回放指标
  python evals/run_eval.py --report reports/report.json

  # 在线（legacy Python 栈）：物化 tiny_app 靶场 → 跑完整漏斗 → 输出指标
  python evals/run_eval.py --live --config config.local.toml

  # 在线扫描自定义靶场（如 pygoat）
  python evals/run_eval.py --live --target /path/to/pygoat --config config.local.toml

  # 在线（新 Rust/Tauri 栈）：headless gloscope-scan → 适配器 → 指标
  python evals/run_eval.py --rust-scan --target /path/to/pygoat
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "legacy-python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gloscope.cli import main as cli_main  # noqa: E402
from gloscope.metrics import evaluate, format_table, load_ground_truth  # noqa: E402
from gloscope.report import report_from_json  # noqa: E402

from rust_report_adapter import build_report  # noqa: E402

FIXTURE_PAYLOAD = Path(__file__).resolve().parent / "fixtures" / "tiny_app" / "app.py.b64"
CODEX_RS_ROOT = REPO_ROOT / "codex-rs"


def resolve_gloscope_scan_path(explicit: str | None) -> Path:
    """定位 `gloscope-scan` 二进制：显式路径优先，否则按 cargo 默认 target 布局
    （`codex-rs/target/{debug,release}/gloscope-scan[.exe]`）猜测，找不到就报错要求
    先 `cargo build -p codex-gloscope-scan`（不在这里自动触发构建——构建耗时以分钟计，
    不应该悄悄发生在一次评测调用里）。"""
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise FileNotFoundError(f"--gloscope-scan-path 指定的文件不存在: {path}")
        return path

    exe_name = "gloscope-scan.exe" if sys.platform == "win32" else "gloscope-scan"
    for profile in ("release", "debug"):
        candidate = CODEX_RS_ROOT / "target" / profile / exe_name
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "找不到 gloscope-scan 二进制。请先在 codex-rs/ 下运行 "
        "`cargo build -p codex-gloscope-scan`（或 --release），"
        "或用 --gloscope-scan-path 显式指定路径。"
    )


def run_rust_scan(
    gloscope_scan_path: Path,
    target: Path,
    gloscope_config: str | None,
    paths: list[str] | None = None,
) -> int:
    argv = [str(gloscope_scan_path), "--target", str(target)]
    if gloscope_config:
        argv += ["--config", gloscope_config]
    if paths:
        argv += ["--paths", ",".join(paths)]
    proc = subprocess.run(argv, shell=False)
    return proc.returncode


def find_latest_findings_jsonl(target: Path, min_run_id: str | None = None) -> Path | None:
    """`gloscope-scan` 把 findings 写到 `<target>/.gloscope/scans/<run_id>/
    findings.jsonl`；run_id 是毫秒时间戳目录名，取字典序最大（=最新）的一个。

    返回 None（而不是报错）当扫描确实跑完（调用方已经检查过 rc == 0）但没有任何
    候选被 `submit_verdict` 验证过——`.gloscope/scans/` 目录本身只在第一次
    `submit_verdict` 调用时才被创建，所以"semgrep 零候选 / triage 全部 drop"这种
    合法的"干净"结果，天然就是目录不存在，不是扫描失败。

    `min_run_id`（可选）过滤掉早于它的 run 目录：当同一个 `target` 被扫描多次
    （如 `cve_replay.py` 对同一个 repo_dir 先扫 parent 再扫 fix），"取字典序最大"
    单独使用会在本次扫描零候选时，把上一次扫描留下的旧目录误当成本次结果——
    调用方在发起扫描前先记录一个时间戳字符串传进来，即可排除这种情况。"""
    scans_dir = target / ".gloscope" / "scans"
    run_dirs = [d for d in scans_dir.iterdir() if d.is_dir()] if scans_dir.is_dir() else []
    if min_run_id is not None:
        run_dirs = [d for d in run_dirs if d.name >= min_run_id]
    if not run_dirs:
        return None
    latest = max(run_dirs, key=lambda d: d.name)
    findings_path = latest / "findings.jsonl"
    if not findings_path.is_file():
        return None
    return findings_path


def materialize_fixture(dest: Path) -> Path:
    """把编码存储的靶场 payload 解码物化到 dest/app.py（明文仅在临时/输出目录存在）。"""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "app.py").write_bytes(base64.b64decode(FIXTURE_PAYLOAD.read_bytes()))
    return dest


def run_eval(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_eval", description="GloScope 四指标评测")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--report", help="离线：对已有 scan 报告计算指标")
    mode.add_argument("--live", action="store_true", help="在线（legacy Python 栈）：物化靶场并跑完整扫描")
    mode.add_argument("--rust-scan", action="store_true",
                      help="在线（新 Rust/Tauri 栈）：headless gloscope-scan + 适配器")
    parser.add_argument("--target", help="live/rust-scan 模式的目标仓库（默认物化 evals/fixtures/tiny_app）")
    parser.add_argument("--config", help="TOML 配置路径（live 模式需要；rust-scan 模式可选，"
                        "对应 gloscope-scan 的 --config/GLOSCOPE_HOME 覆盖）")
    parser.add_argument("--ground-truth", default=str(REPO_ROOT / "evals" / "ground_truth.json"))
    parser.add_argument("--output-dir", default=None, help="live 模式报告目录（默认 evals/results/）")
    parser.add_argument("--skip-triage", action="store_true")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--max-candidates", type=int)
    parser.add_argument("--semgrep-path", default="semgrep",
                        help="semgrep 可执行文件路径（如 venv 内的 semgrep）")
    parser.add_argument("--codex-path", default="codex", help="codex 可执行文件路径")
    parser.add_argument("--gloscope-scan-path",
                        help="rust-scan 模式：gloscope-scan 二进制路径（默认按 cargo target 布局猜测）")
    args = parser.parse_args(argv)

    ground_truth = load_ground_truth(args.ground_truth)

    if args.report:
        report = report_from_json(Path(args.report).read_text(encoding="utf-8"))
    elif args.rust_scan:
        if args.target:
            target = Path(args.target).resolve()
        else:
            target = materialize_fixture(Path(tempfile.mkdtemp(prefix="gloscope-eval-"))).resolve()
            print(f"已物化靶场 tiny_app → {target}")
        gloscope_scan_path = resolve_gloscope_scan_path(args.gloscope_scan_path)
        rc = run_rust_scan(gloscope_scan_path, target, args.config)
        if rc != 0:
            return rc
        findings_path = find_latest_findings_jsonl(target)
        report_dict = build_report(findings_path, str(target))
        out_dir = Path(args.output_dir or str(REPO_ROOT / "evals" / "results"))
        out_dir.mkdir(parents=True, exist_ok=True)
        report_json_path = out_dir / "report.json"
        report_json_path.write_text(
            json.dumps(report_dict, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        report = report_from_json(report_json_path.read_text(encoding="utf-8"))
    else:
        if args.target:
            target = Path(args.target)
        else:
            target = materialize_fixture(Path(tempfile.mkdtemp(prefix="gloscope-eval-")))
            print(f"已物化靶场 tiny_app → {target}")
        out_dir = args.output_dir or str(REPO_ROOT / "evals" / "results")
        scan_argv = ["scan", str(target), "--output-dir", out_dir]
        if args.config:
            scan_argv += ["--config", args.config]
        if args.skip_triage:
            scan_argv.append("--skip-triage")
        if args.skip_verify:
            scan_argv.append("--skip-verify")
        if args.max_candidates:
            scan_argv += ["--max-candidates", str(args.max_candidates)]
        scan_argv += ["--semgrep-path", args.semgrep_path, "--codex-path", args.codex_path]
        rc = cli_main(scan_argv)
        if rc != 0:
            return rc
        report = report_from_json(
            (Path(out_dir) / "report.json").read_text(encoding="utf-8")
        )

    result = evaluate(report, ground_truth)
    print()
    print(format_table(result))
    return 0


if __name__ == "__main__":
    sys.exit(run_eval())
