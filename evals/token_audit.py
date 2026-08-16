"""一次性诊断：捕获 codex exec 完整事件流，用于 token 去向分析。

对 pygoat（大仓库）与 tiny_app（小靶场）各跑一次与 verify._exec 等价的调用，
stdout 事件流存 evals/results/token-audit/*.jsonl。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "evals"))

from cve_replay import fetch_fix  # noqa: E402  (未用，仅保持 sys.path 语义)
from gloscope.config import load_config  # noqa: E402
from gloscope.models import Candidate  # noqa: E402
from gloscope.verify import OUTPUT_SCHEMA, PROMPT_TEMPLATE, _write_codex_home  # noqa: E402

cfg = load_config(REPO / "config.local.toml")


def materialize_tiny(dest: Path) -> Path:
    import base64
    dest.mkdir(parents=True, exist_ok=True)
    payload = (REPO / "evals/fixtures/tiny_app/app.py.b64").read_bytes()
    (dest / "app.py").write_bytes(base64.b64decode(payload))
    return dest


SQLI_CAND = Candidate(
    check_id="python.django.security.injection.tainted-sql-string.tainted-sql-string",
    path="introduction/views.py", start_line=158, end_line=158,
    snippet='    sql_query = "SELECT * FROM introduction_login WHERE user=\'"+name',
    message="Detected user input used to manually construct a SQL string.",
    cwe="CWE-89", category="sql_injection",
)
TINY_CAND = Candidate(
    check_id="python.flask.security.injection.tainted-sql-string.tainted-sql-string",
    path="app.py", start_line=19, end_line=19,
    snippet='    query = "SELECT * FROM users WHERE id = \'" + uid + "\'"',
    message="SQLi", cwe="CWE-89", category="sql_injection",
)

TARGETS = [
    ("pygoat", Path(os.environ["TEMP"]) / "gloscope-pygoat", SQLI_CAND),
    ("tiny_app", materialize_tiny(Path(os.environ["TEMP"]) / "gloscope-token-tiny"), TINY_CAND),
]

out_dir = REPO / "evals/results/token-audit"
out_dir.mkdir(parents=True, exist_ok=True)

for name, target, cand in TARGETS:
    target = target.resolve()
    prompt = PROMPT_TEMPLATE.format(
        target=target, path=cand.path, start_line=cand.start_line,
        end_line=cand.end_line,
        candidate_json=json.dumps(
            {"check_id": cand.check_id, "path": cand.path,
             "start_line": cand.start_line, "end_line": cand.end_line,
             "snippet": cand.snippet, "message": cand.message,
             "cwe": cand.cwe, "category": cand.category},
            ensure_ascii=False, indent=2),
    )
    with tempfile.TemporaryDirectory(prefix="gloscope-audit-") as tmp:
        tmpdir = Path(tmp)
        home = _write_codex_home(cfg)
        schema = tmpdir / "schema.json"
        schema.write_text(json.dumps(OUTPUT_SCHEMA, ensure_ascii=False), encoding="utf-8")
        out = tmpdir / "final.json"
        codex = shutil.which("codex")
        argv = [codex, "exec", "--ephemeral", "--skip-git-repo-check", "--json",
                "-s", "read-only", "-C", str(target),
                "--output-schema", str(schema), "-o", str(out),
                "-c", "model_provider=gloscope", "-m", cfg.verify_model, "-"]
        env = {**os.environ, "CODEX_HOME": str(home),
               "GLOSCOPE_API_KEY": cfg.api_key}
        print(f"[{name}] running …", flush=True)
        proc = subprocess.run(argv, cwd=str(target), env=env, timeout=600,
                              capture_output=True, text=True, input=prompt)
        stream_file = out_dir / f"{name}.jsonl"
        stream_file.write_text(proc.stdout, encoding="utf-8")
        print(f"[{name}] rc={proc.returncode} events={len(proc.stdout.splitlines())} "
              f"-> {stream_file.name}", flush=True)
