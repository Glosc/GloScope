"""Slice 8 — cli: scan/eval 子命令装配。接缝：main(argv, factory=...)，factory 注入假流水线。
"""

from __future__ import annotations

import json
from pathlib import Path

from gloscope.cli import main
from gloscope.config import Config
from gloscope.models import Candidate, Finding, ScanReport, TriageResult, Verification
from gloscope.pipeline import PipelineOptions
from gloscope.report import render_json


class FakePipeline:
    def __init__(self, report):
        self.report = report

    def run(self, target):
        self.report.target = str(target)
        return self.report


def sample_report():
    return ScanReport(
        target="sample",
        findings=[
            Finding(
                candidate=Candidate("r.sqli", "app.py", 12, 12, "snip", "m",
                                    "CWE-89", "sql_injection"),
                triage=TriageResult(True, "值得深查", tokens_in=10, tokens_out=5),
                verification=Verification("confirmed", "CWE-89", ["app.py:12 - sink"], "high"),
            ),
        ],
        semgrep_seconds=1.0, triage_seconds=2.0, verify_seconds=3.0,
    )


class FactorySpy:
    """记录 cli 装配参数，返回假流水线。"""

    def __init__(self, report):
        self.report = report
        self.calls: list[dict] = []

    def __call__(self, cfg, options, **kw):
        self.calls.append({"cfg": cfg, "options": options, **kw})
        return FakePipeline(self.report)


def test_scan_writes_reports_and_prints_summary(tmp_path, capsys):
    spy = FactorySpy(sample_report())
    out_dir = tmp_path / "out"
    rc = main(["scan", str(tmp_path), "--skip-triage", "--skip-verify",
               "--output-dir", str(out_dir)], factory=spy)
    assert rc == 0
    md = (out_dir / "report.md").read_text(encoding="utf-8")
    js = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    sarif = json.loads((out_dir / "report.sarif").read_text(encoding="utf-8"))
    assert "确认" in md
    assert js["stats"]["confirmed"] == 1
    assert sarif["version"] == "2.1.0"  # SARIF 一并落盘
    assert len(sarif["runs"][0]["results"]) == 1  # 仅 confirmed 入
    out = capsys.readouterr().out
    assert "confirmed" in out and "report.md" in out


def test_scan_passes_options_and_semgrep_only_needs_no_config(tmp_path):
    spy = FactorySpy(sample_report())
    rc = main(["scan", str(tmp_path), "--skip-triage", "--skip-verify",
               "--max-candidates", "5", "--semgrep-rules", "p/owasp-top-ten",
               "--output-dir", str(tmp_path / "o")], factory=spy)
    assert rc == 0
    call = spy.calls[0]
    assert call["cfg"] is None  # semgrep-only 无需 provider 配置
    assert call["options"] == PipelineOptions(skip_triage=True, skip_verify=True,
                                              max_candidates=5)
    assert call["semgrep_rules"] == "p/owasp-top-ten"


def test_scan_with_llm_layers_loads_config(tmp_path):
    spy = FactorySpy(sample_report())
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text(
        '[provider]\nbase_url = "https://x"\napi_key = "k"\n\n'
        '[models]\ntriage_model = "t"\n',
        encoding="utf-8",
    )
    rc = main(["scan", str(tmp_path), "--skip-verify", "--config", str(cfg_file),
               "--output-dir", str(tmp_path / "o")], factory=spy)
    assert rc == 0
    assert isinstance(spy.calls[0]["cfg"], Config)
    assert spy.calls[0]["options"].skip_verify is True
    assert spy.calls[0]["options"].skip_triage is False


def test_scan_missing_config_fails_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GLOSCOPE_CONFIG", raising=False)
    monkeypatch.delenv("GLOSCOPE_API_KEY", raising=False)
    rc = main(["scan", str(tmp_path), "--skip-verify",
               "--output-dir", str(tmp_path / "o")], factory=FactorySpy(sample_report()))
    assert rc == 1
    assert "配置" in capsys.readouterr().err


def test_eval_prints_metrics_table(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    report_path.write_text(render_json(sample_report()), encoding="utf-8")
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps(
        [{"path": "app.py", "category": "sql_injection", "line": 12}]), encoding="utf-8")
    rc = main(["eval", str(report_path), "--ground-truth", str(gt_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "召回率" in out and "full" in out


def test_eval_bad_report_fails(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    report_path.write_text(render_json(sample_report()), encoding="utf-8")
    bad_gt = tmp_path / "bad-gt.json"
    bad_gt.write_text(json.dumps([{"path": "a.py", "category": "rce", "line": 1}]),
                      encoding="utf-8")
    rc = main(["eval", str(report_path), "--ground-truth", str(bad_gt)])
    assert rc == 1
    assert "rce" in capsys.readouterr().err
