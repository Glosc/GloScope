"""评测脚本：固定靶场 → 四指标（召回率、误报数、token 成本、耗时）+ 漏斗分层对比。

用法：
  # 离线：对一份 scan 报告回放指标
  python evals/run_eval.py --report reports/report.json

  # 在线：物化 tiny_app 靶场 → 跑完整漏斗 → 输出指标
  python evals/run_eval.py --live --config config.local.toml

  # 在线扫描自定义靶场（如 pygoat）
  python evals/run_eval.py --live --target /path/to/pygoat --config config.local.toml
"""

from __future__ import annotations

import argparse
import base64
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "legacy-python"))

from gloscope.cli import main as cli_main  # noqa: E402
from gloscope.metrics import evaluate, format_table, load_ground_truth  # noqa: E402
from gloscope.report import report_from_json  # noqa: E402

FIXTURE_PAYLOAD = Path(__file__).resolve().parent / "fixtures" / "tiny_app" / "app.py.b64"


def materialize_fixture(dest: Path) -> Path:
    """把编码存储的靶场 payload 解码物化到 dest/app.py（明文仅在临时/输出目录存在）。"""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "app.py").write_bytes(base64.b64decode(FIXTURE_PAYLOAD.read_bytes()))
    return dest


def run_eval(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_eval", description="GloScope 四指标评测")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--report", help="离线：对已有 scan 报告计算指标")
    mode.add_argument("--live", action="store_true", help="在线：物化靶场并跑完整扫描")
    parser.add_argument("--target", help="live 模式的目标仓库（默认物化 evals/fixtures/tiny_app）")
    parser.add_argument("--config", help="TOML 配置路径（live 模式需要）")
    parser.add_argument("--ground-truth", default=str(REPO_ROOT / "evals" / "ground_truth.json"))
    parser.add_argument("--output-dir", default=None, help="live 模式报告目录（默认 evals/results/）")
    parser.add_argument("--skip-triage", action="store_true")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--max-candidates", type=int)
    parser.add_argument("--semgrep-path", default="semgrep",
                        help="semgrep 可执行文件路径（如 venv 内的 semgrep）")
    parser.add_argument("--codex-path", default="codex", help="codex 可执行文件路径")
    args = parser.parse_args(argv)

    ground_truth = load_ground_truth(args.ground_truth)

    if args.report:
        report = report_from_json(Path(args.report).read_text(encoding="utf-8"))
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
