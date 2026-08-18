"""Slice 9 — evals: 靶场 fixture 完整性 + 评测脚本离线模式。"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

LEGACY_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = LEGACY_ROOT.parent
PAYLOAD = REPO_ROOT / "evals" / "fixtures" / "tiny_app" / "app.py.b64"
RUN_EVAL = REPO_ROOT / "evals" / "run_eval.py"


def test_fixture_payload_decodes_to_flask_app():
    text = base64.b64decode(PAYLOAD.read_bytes()).decode("utf-8")
    # 三条已知漏洞的路由都在，且是刻意脆弱的靶场
    assert '"/user"' in text and '"/fetch"' in text and '"/notes"' in text
    assert "故意脆弱" in text  # 自我声明，防误用
    assert "request.args.get" in text


def test_ground_truth_matches_fixture(tmp_path):
    sys.path.insert(0, str(REPO_ROOT / "evals"))
    try:
        from run_eval import materialize_fixture

        target = materialize_fixture(tmp_path / "tiny_app")
        app_py = (target / "app.py").read_text(encoding="utf-8")
        assert "Flask" in app_py
    finally:
        sys.path.pop(0)

    gt = json.loads((REPO_ROOT / "evals" / "ground_truth.json").read_text(encoding="utf-8"))
    assert len(gt) == 3
    assert {item["category"] for item in gt} == {"sql_injection", "ssrf", "path_traversal"}
    assert all(item["path"] == "app.py" for item in gt)
    # ground truth 标注的行落在物化后的文件里
    for item in gt:
        assert 0 < item["line"] <= app_py.count("\n") + 1


def test_run_eval_offline_from_report(tmp_path, capsys):
    sys.path.insert(0, str(REPO_ROOT / "evals"))
    from run_eval import run_eval  # noqa: E402

    # 合成一份「三条 GT 全中、零误报」的报告
    report = {
        "target": "tiny_app",
        "created_at": "",
        "truncated": 0,
        "stats": {
            "candidates": 3, "kept": 3, "dropped": 0,
            "confirmed": 3, "false_positives": 0, "inconclusive": 0, "errors": 0,
            "triage_tokens_in": 300, "triage_tokens_out": 30,
            "verify_tokens_in": 1500, "verify_tokens_out": 300,
            "tokens_total": 2130,
            "semgrep_seconds": 2.0, "triage_seconds": 3.0, "verify_seconds": 60.0,
        },
        "findings": [
            {
                "candidate": {"check_id": "r1", "path": "app.py", "start_line": 19,
                               "end_line": 19, "snippet": "s", "message": "m",
                               "cwe": "CWE-89", "category": "sql_injection",
                               "source": "semgrep"},
                "triage": {"keep": True, "reason": "r", "model": "t",
                           "tokens_in": 100, "tokens_out": 10},
                "verification": {"verdict": "confirmed", "cwe": "CWE-89",
                                  "taint_path": ["app.py:19 - sink"], "confidence": "high",
                                  "poc_idea": "", "explanation": "",
                                  "error": None, "model": "v",
                                  "tokens_in": 500, "tokens_out": 100},
            },
            {
                "candidate": {"check_id": "r2", "path": "app.py", "start_line": 27,
                               "end_line": 27, "snippet": "s", "message": "m",
                               "cwe": "CWE-918", "category": "ssrf",
                               "source": "semgrep"},
                "triage": {"keep": True, "reason": "r", "model": "t",
                           "tokens_in": 100, "tokens_out": 10},
                "verification": {"verdict": "confirmed", "cwe": "CWE-918",
                                  "taint_path": [], "confidence": "high",
                                  "poc_idea": "", "explanation": "",
                                  "error": None, "model": "v",
                                  "tokens_in": 500, "tokens_out": 100},
            },
            {
                "candidate": {"check_id": "r3", "path": "app.py", "start_line": 36,
                               "end_line": 36, "snippet": "s", "message": "m",
                               "cwe": "CWE-22", "category": "path_traversal",
                               "source": "semgrep"},
                "triage": {"keep": True, "reason": "r", "model": "t",
                           "tokens_in": 100, "tokens_out": 10},
                "verification": {"verdict": "confirmed", "cwe": "CWE-22",
                                  "taint_path": [], "confidence": "medium",
                                  "poc_idea": "", "explanation": "",
                                  "error": None, "model": "v",
                                  "tokens_in": 500, "tokens_out": 100},
            },
        ],
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")

    rc = run_eval(["--report", str(report_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "召回率" in out
    assert "| full | 1.000 | 0 |" in out  # 三中零误报


def test_run_eval_is_runnable_as_script():
    proc = subprocess.run(
        [sys.executable, str(RUN_EVAL), "--help"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0
    assert "--live" in proc.stdout and "--report" in proc.stdout
