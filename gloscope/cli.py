"""CLI 入口：gloscope scan <target> / gloscope eval <report.json>。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, TypeAlias

from gloscope.config import Config, ConfigError, load_config
from gloscope.metrics import evaluate, format_table, load_ground_truth
from gloscope.models import ScanReport
from gloscope.pipeline import Pipeline, PipelineOptions
from gloscope.report import render_json, render_markdown, render_sarif, report_from_json
from gloscope.semgrep_runner import SemgrepCandidateGenerator, SemgrepError
from gloscope.triage import OpenAITriageClient
from gloscope.verify import CodexVerifier

# factory: (cfg, options, 装配参数...) -> Pipeline。可注入以便测试。
PipelineFactory: TypeAlias = Callable[..., Pipeline]


def _default_factory(
    cfg: Config | None,
    options: PipelineOptions,
    *,
    semgrep_rules: str,
    semgrep_path: str,
    codex_path: str,
    diff_base: str | None = None,
    paths: list[str] | None = None,
    no_callgraph: bool = False,
) -> Pipeline:
    generator = SemgrepCandidateGenerator(
        semgrep_path=semgrep_path, rules=semgrep_rules, diff_base=diff_base, paths=paths
    )
    triager = OpenAITriageClient(cfg) if cfg and not options.skip_triage else None
    verifier = (
        CodexVerifier(cfg, codex_path=codex_path, callgraph=not no_callgraph)
        if cfg and not options.skip_verify else None
    )
    return Pipeline(generator, triager=triager, verifier=verifier, options=options)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gloscope",
        description="寻幽 — 漏斗式漏洞审计：semgrep 找候选 → LLM 分诊 → codex exec 深度验证",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="扫描目标仓库")
    p_scan.add_argument("target", help="目标仓库路径（Python Web 项目）")
    p_scan.add_argument("--config", help="TOML 配置路径（默认发现 ./gloscope.toml 或 ./config.local.toml）")
    p_scan.add_argument("--skip-triage", action="store_true", help="跳过 LLM 分诊层")
    p_scan.add_argument("--skip-verify", action="store_true", help="跳过 codex 深度验证层")
    p_scan.add_argument("--max-candidates", type=int, metavar="N", help="限制进入漏斗的候选数（控制成本）")
    p_scan.add_argument("--categories", metavar="CATS",
                        help="逗号分隔的类别白名单（如 sql_injection,ssrf,path_traversal），"
                             "只让这些类别的候选进漏斗")
    p_scan.add_argument("--output-dir", default="reports", help="报告输出目录（默认 reports/）")
    p_scan.add_argument("--semgrep-rules", default="auto", help="semgrep 规则集（默认 auto）")
    scope = p_scan.add_mutually_exclusive_group()
    scope.add_argument("--diff-base", metavar="REF",
                       help="增量扫描：只扫与该 git ref（如 origin/main）有差异的文件")
    scope.add_argument("--paths", metavar="FILES",
                       help="只扫这些文件（逗号分隔，相对目标根；CVE 回放等定向扫描用）")
    p_scan.add_argument("--semgrep-path", default="semgrep", help="semgrep 可执行文件路径")
    p_scan.add_argument("--codex-path", default="codex", help="codex 可执行文件路径")
    p_scan.add_argument("--no-callgraph", action="store_true",
                        help="禁用验证层的调用图 MCP 工具（http_entrypoints/resolve 等）")

    p_eval = sub.add_parser("eval", help="对扫描报告计算四指标（召回率/误报/token/耗时）")
    p_eval.add_argument("report", help="scan 产生的 report.json")
    p_eval.add_argument("--ground-truth", default="evals/ground_truth.json",
                        help="ground truth JSON 路径")
    return parser


def _cmd_scan(args: argparse.Namespace, factory: PipelineFactory) -> int:
    options = PipelineOptions(
        skip_triage=args.skip_triage,
        skip_verify=args.skip_verify,
        max_candidates=args.max_candidates,
        categories=(
            {c.strip() for c in args.categories.split(",") if c.strip()}
            if args.categories else None
        ),
    )
    cfg: Config | None = None
    needs_llm = not (options.skip_triage and options.skip_verify)
    try:
        if needs_llm:
            cfg = load_config(args.config)
    except ConfigError as e:
        print(f"配置错误: {e}", file=sys.stderr)
        return 1

    pipeline = factory(
        cfg, options,
        semgrep_rules=args.semgrep_rules,
        semgrep_path=args.semgrep_path,
        codex_path=args.codex_path,
        diff_base=args.diff_base,
        paths=[p.strip() for p in args.paths.split(",") if p.strip()] if args.paths else None,
        no_callgraph=args.no_callgraph,
    )
    try:
        report = pipeline.run(Path(args.target))
    except SemgrepError as e:
        print(f"扫描失败: {e}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (out_dir / "report.json").write_text(render_json(report), encoding="utf-8")
    (out_dir / "report.sarif").write_text(render_sarif(report), encoding="utf-8")

    s = report.stats()
    print(
        f"扫描完成：候选 {s.candidates} · 确认 (confirmed) {s.confirmed} · "
        f"误报 {s.false_positives} · 存疑 {s.inconclusive} · token 合计 {s.tokens_total}"
    )
    print(f"报告已写入: {out_dir / 'report.md'} / report.json / report.sarif")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    try:
        report = report_from_json(Path(args.report).read_text(encoding="utf-8"))
        ground_truth = load_ground_truth(args.ground_truth)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"评测输入错误: {e}", file=sys.stderr)
        return 1
    print(format_table(evaluate(report, ground_truth)))
    return 0


def main(argv: list[str] | None = None, factory: PipelineFactory | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args, factory or _default_factory)
    return _cmd_eval(args)


if __name__ == "__main__":
    sys.exit(main())
