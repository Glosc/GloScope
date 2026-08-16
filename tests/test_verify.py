"""Slice 4 — verify: codex exec 子进程包装（自包含 prompt + 输出契约 + 只读沙箱 + 配置注入）。
接缝：CodexVerifier.verify(candidate, target)，runner 可注入（fake runner 解析 argv 写 -o 文件）。
"""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

import pytest

from gloscope.config import Config
from gloscope.models import Candidate
from gloscope.verify import OUTPUT_SCHEMA, CodexVerifier

# 测试专用占位值，非真实凭据
_FAKE_KEY = "fake-key-for-unit-tests"

CFG = Config(
    base_url="https://api.deepseek.com",
    api_key=_FAKE_KEY,
    triage_model="deepseek-chat",
    verify_model="deepseek-reasoner",
)

CAND = Candidate(
    check_id="python.flask.security.insecure-sql-query.insecure-sql-query",
    path="app.py",
    start_line=12,
    end_line=12,
    snippet="    run_query(dynamically_built_stmt)",
    message="非参数化 SQL 查询",
    cwe="CWE-89",
    category="sql_injection",
)

GOOD_OUTPUT = {
    "verdict": "confirmed",
    "cwe": "CWE-89",
    "taint_path": ["app.py:5 - request.args.get 取参", "app.py:12 - sink"],
    "confidence": "high",
    "poc_idea": "id 参数传特殊构造的输入观察查询结构变化",
    "explanation": "请求参数未经净化直接进入查询构造。",
}


class FakeCodexRunner:
    """模拟 codex：--version 调用返回版本串；exec 调用把 result_json 写到 -o 文件。"""

    def __init__(self, result=GOOD_OUTPUT, returncode=0, stdout="", stderr="",
                 raise_exc=None, dont_write=False, version_returncode=0):
        self.result, self.returncode = result, returncode
        self.stdout, self.stderr = stdout, stderr
        self.raise_exc = raise_exc
        self.dont_write = dont_write
        self.version_returncode = version_returncode
        self.calls: list[dict] = []

    @property
    def exec_calls(self) -> list[dict]:
        return [c for c in self.calls if "exec" in c["argv"]]

    def __call__(self, argv, cwd, env, timeout, stdin_text=None):
        self.calls.append({"argv": list(argv), "cwd": cwd, "env": dict(env),
                           "timeout": timeout, "stdin": stdin_text})
        if self.raise_exc and "exec" in argv:
            raise self.raise_exc
        if "--version" in argv:
            out = "codex-cli 0.147.0" if self.version_returncode == 0 else ""
            return self.version_returncode, out, ""
        # 临时文件在 _exec 返回后即销毁，调用时快照其内容
        home = Path(env["CODEX_HOME"])
        self.calls[-1]["codex_config"] = (home / "config.toml").read_text(encoding="utf-8")
        if not self.dont_write:
            out_path = Path(argv[argv.index("-o") + 1])
            out_path.write_text(json.dumps(self.result), encoding="utf-8")
        return self.returncode, self.stdout, self.stderr


def make_verifier(runner, **kw):
    return CodexVerifier(CFG, runner=runner, **kw)


def test_codex_argv_readonly_sandbox_schema_and_model(tmp_path, monkeypatch):
    monkeypatch.setattr("gloscope.verify.shutil.which", lambda n: None)  # 环境无关
    runner = FakeCodexRunner()
    make_verifier(runner).verify(CAND, tmp_path)
    argv = runner.exec_calls[0]["argv"]
    assert argv[0] == "codex"
    assert "exec" in argv
    assert "-s" in argv and argv[argv.index("-s") + 1] == "read-only"
    assert "--ephemeral" in argv
    assert "--skip-git-repo-check" in argv
    assert "--output-schema" in argv
    assert "-o" in argv
    assert "--json" in argv
    # 工作根目录指向目标仓库
    assert "-C" in argv and argv[argv.index("-C") + 1] == str(tmp_path)
    # 模型与 provider 注入
    assert "-m" in argv and argv[argv.index("-m") + 1] == "deepseek-reasoner"
    assert "-c" in argv and "model_provider=gloscope" in argv


def test_codex_home_injects_model_provider_config(tmp_path):
    runner = FakeCodexRunner()
    make_verifier(runner).verify(CAND, tmp_path)
    env = runner.exec_calls[0]["env"]
    home = Path(env["CODEX_HOME"])
    assert env["GLOSCOPE_API_KEY"] == _FAKE_KEY
    assert home == Path.home() / ".gloscope" / "codex-home"  # 独立目录，不碰 ~/.codex
    import tempfile
    assert not str(home).startswith(str(tempfile.gettempdir()))  # codex 拒绝 temp 下的 CODEX_HOME
    cfg = tomllib.loads(runner.exec_calls[0]["codex_config"])
    prov = cfg["model_providers"]["gloscope"]
    assert prov["base_url"] == "https://api.deepseek.com"
    assert prov["env_key"] == "GLOSCOPE_API_KEY"
    assert prov["wire_api"] == "responses"  # codex 0.147+ 硬性要求


def test_prompt_travels_via_stdin_not_argv(tmp_path):
    """Windows 实测：含引号/中文的长 prompt 经 codex.CMD 会被 cmd.exe 破坏参数边界
    （schema 路径被污染 → os error 2/3）。prompt 必须走 stdin（argv 以 `-` 结尾）。
    """
    runner = FakeCodexRunner()
    make_verifier(runner).verify(CAND, tmp_path)
    argv = runner.exec_calls[0]["argv"]
    stdin_text = runner.exec_calls[0]["stdin"]
    assert argv[-1] == "-"  # codex exec 的 stdin 模式
    # prompt 内容不进命令行
    assert not any(CAND.check_id in a for a in argv if isinstance(a, str))
    assert stdin_text is not None
    assert CAND.check_id in stdin_text
    assert "app.py" in stdin_text and "12" in stdin_text
    # 方法论 + 输出契约
    assert "污点" in stdin_text
    assert "verdict" in stdin_text and "taint_path" in stdin_text
    assert "file.py:42" in stdin_text  # taint_path 格式示例


def test_output_schema_file_strict(tmp_path):
    schema = OUTPUT_SCHEMA
    assert set(schema["required"]) == {
        "verdict", "cwe", "taint_path", "confidence", "poc_idea", "explanation"
    }
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]["verdict"]["enum"]) == {
        "confirmed", "false_positive", "inconclusive"
    }
    assert set(schema["properties"]["confidence"]["enum"]) == {"high", "medium", "low"}


def test_parses_confirmed_verification_with_tokens(tmp_path):
    # codex 0.147 --json 真实事件形状：顶层 turn.completed + usage；多 turn 累计
    token_stream = "\n".join([
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 5000, "output_tokens": 40}}),
        '{"type": "agent_message", "message": "thinking..."}',
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 3000, "cached_input_tokens": 2800, "output_tokens": 60}}),
    ])
    runner = FakeCodexRunner(stdout=token_stream)
    v = make_verifier(runner).verify(CAND, tmp_path)
    assert v.verdict == "confirmed"
    assert v.cwe == "CWE-89"
    assert v.taint_path == ["app.py:5 - request.args.get 取参", "app.py:12 - sink"]
    assert v.confidence == "high"
    assert "id 参数" in v.poc_idea
    assert v.error is None
    assert (v.tokens_in, v.tokens_out) == (8000, 100)  # 两个 turn 累计
    assert v.model == "deepseek-reasoner"


def test_nonzero_exit_is_inconclusive_with_error(tmp_path):
    runner = FakeCodexRunner(returncode=1, stderr="model provider error")
    v = make_verifier(runner).verify(CAND, tmp_path)
    assert v.verdict == "inconclusive"
    assert "model provider error" in (v.error or "")


def test_timeout_is_inconclusive(tmp_path):
    runner = FakeCodexRunner(raise_exc=subprocess.TimeoutExpired(cmd="codex", timeout=5))
    v = make_verifier(runner).verify(CAND, tmp_path)
    assert v.verdict == "inconclusive"
    assert v.error


def test_missing_output_file_is_inconclusive(tmp_path):
    runner = FakeCodexRunner(dont_write=True, stdout="")
    v = make_verifier(runner).verify(CAND, tmp_path)
    assert v.verdict == "inconclusive"
    assert v.error


def test_bad_output_json_is_inconclusive(tmp_path):
    runner = FakeCodexRunner(result={"unexpected": "shape"})
    v = make_verifier(runner).verify(CAND, tmp_path)
    assert v.verdict == "inconclusive"
    assert v.error


def test_version_probe_runs_once_and_blocks_exec_on_failure(tmp_path):
    runner = FakeCodexRunner(version_returncode=1)
    verifier = make_verifier(runner)
    v1 = verifier.verify(CAND, tmp_path)
    v2 = verifier.verify(CAND, tmp_path)
    assert v1.verdict == "inconclusive" and "codex --version" in (v1.error or "")
    assert v2.verdict == "inconclusive"  # 探测结果缓存，第二次不再探测
    assert runner.exec_calls == []  # 探测失败时不进入 exec
    assert len([c for c in runner.calls if "--version" in c["argv"]]) == 1


def test_version_probe_precedes_exec_once(tmp_path, monkeypatch):
    monkeypatch.setattr("gloscope.verify.shutil.which", lambda n: None)  # 环境无关
    runner = FakeCodexRunner()
    verifier = make_verifier(runner)  # 流水线内单个 verifier 服务全部候选
    verifier.verify(CAND, tmp_path)
    verifier.verify(CAND, tmp_path)
    version_calls = [c for c in runner.calls if "--version" in c["argv"]]
    assert len(version_calls) == 1  # 多候选只探测一次
    assert len(runner.exec_calls) == 2
    assert runner.calls[0]["argv"][:2] == ["codex", "--version"]


def test_codex_name_resolved_via_pathext(tmp_path, monkeypatch):
    """Windows：npm 安装的 codex 是 codex.cmd，subprocess 不解析裸名 → which 预解析。"""
    monkeypatch.setattr("gloscope.verify.shutil.which", lambda n: r"C:\nodejs\codex.CMD")
    runner = FakeCodexRunner()
    CodexVerifier(CFG, codex_path="codex", runner=runner).verify(CAND, tmp_path)
    assert runner.calls[0]["argv"][0] == r"C:\nodejs\codex.CMD"
    monkeypatch.setattr("gloscope.verify.shutil.which", lambda n: None)
    runner2 = FakeCodexRunner()
    CodexVerifier(CFG, codex_path="codex", runner=runner2).verify(CAND, tmp_path)
    assert runner2.calls[0]["argv"][0] == "codex"


def test_target_resolved_to_absolute_path(tmp_path, monkeypatch):
    """Windows 实测：相对路径 cwd/-C 传给 codex 的 .cmd shim 报 os error 3，必须绝对化。"""
    monkeypatch.setattr("gloscope.verify.shutil.which", lambda n: None)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "t").mkdir()
    runner = FakeCodexRunner()
    CodexVerifier(CFG, runner=runner).verify(CAND, Path("t"))
    call = runner.exec_calls[0]
    argv = call["argv"]
    assert argv[argv.index("-C") + 1] == str(tmp_path / "t")
    assert call["cwd"] == tmp_path / "t"
