"""Rust/Tauri 栈适配器：`gloscope-scan` 落盘的 `findings.jsonl`（camelCase，逐行一个
`{candidate, verification}` 对象）→ legacy `report_from_json()` 能解析的 `report.json`
（snake_case，`{target, created_at, truncated, stats, findings: [{candidate, triage, verification}]}`）。

两边字段含义一致，只是大小写风格不同——这里只做重命名+包装，不重新设计 schema。
`triage` 字段固定为 null：`evaluate()` 只读 candidate.path/category（经 verification.cwe
优先）做匹配，不依赖 triage 数据（M9 范围内不需要单独捕获 triage 工具的中间结果）。

用法：
  python evals/rust_report_adapter.py --findings <run-dir>/findings.jsonl \
      --target /path/to/target --output report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_CAMEL_RE_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_RE_2 = re.compile(r"([a-z0-9])([A-Z])")


def camel_to_snake(name: str) -> str:
    """`checkId` -> `check_id`, `executionContext` -> `execution_context`, etc."""
    s1 = _CAMEL_RE_1.sub(r"\1_\2", name)
    return _CAMEL_RE_2.sub(r"\1_\2", s1).lower()


def _snake_keys(obj: dict) -> dict:
    return {camel_to_snake(k): v for k, v in obj.items()}


def load_findings(findings_path: Path) -> list[dict]:
    """逐行解析 `findings.jsonl`；空行跳过，格式错误直接抛错（不静默丢数据，
    因为这是评测输入，数据缺失会悄悄压低召回率而不报错）。"""
    findings: list[dict] = []
    text = findings_path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"{findings_path}:{lineno} 不是合法 JSON: {err}") from err
        candidate = _snake_keys(raw["candidate"])
        verification = _snake_keys(raw["verification"])
        findings.append({"candidate": candidate, "triage": None, "verification": verification})
    return findings


def build_report(findings_path: Path, target: str) -> dict:
    return {
        "target": target,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "truncated": 0,
        "stats": {},
        "findings": load_findings(findings_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust_report_adapter",
        description="gloscope-scan 的 findings.jsonl -> legacy report_from_json 兼容的 report.json",
    )
    parser.add_argument("--findings", required=True, help="gloscope-scan 产出的 findings.jsonl 路径")
    parser.add_argument("--target", required=True, help="被扫描的目标仓库路径（写入 report.target）")
    parser.add_argument("--output", required=True, help="输出 report.json 路径")
    args = parser.parse_args(argv)

    report = build_report(Path(args.findings), args.target)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已写入 {output_path}（{len(report['findings'])} 条 finding）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
