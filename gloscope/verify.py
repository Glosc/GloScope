"""第三层：codex exec 深度验证。
每候选一个自包含 prompt（候选 JSON + 方法论 + 输出契约），--output-schema 强制 JSON，
只读沙箱；provider 通过临时 CODEX_HOME 注入，绕开 codex 自带 OpenAI 登录。
任何执行失败 → inconclusive + error（fail-open，不吞候选）。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, TypeAlias

from gloscope.callgraph import build_callgraph
from gloscope.config import Config
from gloscope.models import Candidate, Verification, asdict_jsonable

# runner: (argv, cwd, env, timeout, stdin_text) -> (returncode, stdout, stderr)。可注入以便测试。
Runner: TypeAlias = Callable[[list[str], Path, dict, float, "str | None"], "tuple[int, str, str]"]

PROVIDER_ID = "gloscope"
ENV_KEY = "GLOSCOPE_API_KEY"

# 验证层输出契约（codex --output-schema 要求 strict schema：全字段 required + 禁额外字段）
OUTPUT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "false_positive", "inconclusive"],
            "description": "confirmed=真实可达漏洞；false_positive=误报；inconclusive=证据不足",
        },
        "cwe": {"type": "string", "description": "CWE 编号，如 CWE-89；未知则空字符串"},
        "taint_path": {
            "type": "array",
            "items": {"type": "string"},
            "description": "污点链每一步，格式 path/to/file.py:42 - 该步说明",
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "poc_idea": {"type": "string", "description": "利用/验证思路；无则空字符串"},
        "explanation": {"type": "string", "description": "结论依据：可达性、净化情况等"},
        # 动态 PoC 请求规格（扁平字段，空串=不适用）：执行器只发 HTTP，不执行代码
        "poc_method": {"type": "string", "description": "HTTP 方法，如 GET/POST；不适用为空"},
        "poc_path": {"type": "string", "description": "请求路径，如 /user；不适用为空"},
        "poc_query": {"type": "string", "description": "查询串（不含 ?），如 id=' OR '1'='1"},
        "poc_body": {"type": "string", "description": "请求体（form/JSON 文本）；无则空"},
        "poc_signal": {"type": "string", "description": "差分信号：仅当漏洞被触发时出现在响应中的稳定子串"},
    },
    "required": ["verdict", "cwe", "taint_path", "confidence", "poc_idea", "explanation",
                 "poc_method", "poc_path", "poc_query", "poc_body", "poc_signal"],
    "additionalProperties": False,
}

PROMPT_TEMPLATE = """你是一名资深 Web 安全审计专家，正在验证一个静态扫描候选是否为真实漏洞。
目标仓库根目录就是你的工作目录（{target}），你已拥有只读的读文件/grep/glob 工具，可自由探索。

方法论（按序执行）：
1. 定位候选：读 {path} 第 {start_line}-{end_line} 行附近源码，确认 sink 存在。
2. 回溯污点来源：source 是否用户可控（HTTP 参数、请求体、header、上传文件名等）。
3. 追踪 source → sink 的完整调用链，检查每一步是否存在有效净化
   （参数化查询、白名单校验、路径规范化+前缀校验、URL host 白名单等）。
4. 判断可达性：路由/入口是否注册、该分支是否可被外部请求触达。
5. 下结论：只有「污点可达且无有效净化」才 confirmed；能证明净化/不可达则 false_positive；
   证据不足（如关键文件缺失）则 inconclusive。

候选 JSON（来自 semgrep）：
{candidate_json}

输出契约（最终回复必须是且仅是一个符合 schema 的 JSON 对象）：
- verdict: "confirmed" | "false_positive" | "inconclusive"
- cwe: "CWE-89" 形式，无法判断则空字符串
- taint_path: 数组，每项 "path/to/file.py:42 - 该步说明"，confirmed 时必须给出完整链
- confidence: "high" | "medium" | "low"
- poc_idea: 如何构造请求验证（无则空字符串）
- explanation: 结论依据（可达性、净化情况等）
- poc_method/poc_path/poc_query/poc_body/poc_signal: 若 confirmed 且可远程触发，
  给出最小差分请求规格与信号（signal 选仅在漏洞触发时出现的稳定子串）；否则全空串。

若附有「HTTP 入口索引」，直接引用其中的路由入口（file:line），不必再搜索路由注册。"""


def _real_runner(
    argv: list[str], cwd: Path, env: dict, timeout: float, stdin_text: str | None = None
) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv, cwd=str(cwd), env=env, timeout=timeout, capture_output=True,
        text=True, input=stdin_text,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _write_codex_home(cfg: Config) -> Path:
    """生成 codex model_providers 配置：编排层与分诊层共用同一 provider 凭据。

    CODEX_HOME 放用户目录下（~/.gloscope/codex-home）：codex 拒绝在系统临时目录
    创建 PATH aliases（helper binaries），且不能动用户真实的 ~/.codex。config.toml
    幂等覆盖写入。注意：codex exec 实测静默忽略 [mcp_servers] 段（仅 TUI 生效），
    调用图辅助改由 prompt 注入（见 _entrypoint_index）。
    """
    home = Path.home() / ".gloscope" / "codex-home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(
        f"""[model_providers.{PROVIDER_ID}]
name = "GloScope user provider"
base_url = "{cfg.base_url}"
env_key = "{ENV_KEY}"
wire_api = "{cfg.wire_api}"
""",
        encoding="utf-8",
    )
    return home


def _entrypoint_index(target: Path, max_lines: int = 150) -> str:
    """调用图 HTTP 入口索引（静态提取，注入 prompt）。

    codex exec 对 [mcp_servers] 配置静默忽略（2026-08 实测，RUST_LOG 无启动日志），
    退化为零协议风险的 prompt 注入：验证 agent 的惯常第一步（找路由入口）直接给出。
    """
    try:
        graph = build_callgraph(target)
    except Exception:  # noqa: BLE001 — 索引失败不阻断验证
        return ""
    if not graph.entrypoints:
        return ""
    lines = [
        f"{e.method:<10} {e.path:<30} {e.handler} ({e.file}:{e.line})"
        for e in graph.entrypoints
    ]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"…（共 {len(graph.entrypoints)} 个入口，已截断）"]
    return "\n".join(lines)


def _parse_tokens(stdout: str) -> tuple[int, int]:
    """从 codex --json 事件流（JSONL）尽力提取 token 用量；解析不了就返回 0。

    codex 0.147 真实形状：顶层 {"type": "turn.completed", "usage": {input_tokens,
    output_tokens, ...}}，一个会话多个 turn 需累计。
    """
    tokens_in = tokens_out = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        usage = event.get("usage") if isinstance(event, dict) else None
        if isinstance(usage, dict) and "input_tokens" in usage:
            tokens_in += int(usage.get("input_tokens", 0))
            tokens_out += int(usage.get("output_tokens", 0))
    return tokens_in, tokens_out


class CodexVerifier:
    def __init__(
        self,
        cfg: Config,
        codex_path: str = "codex",
        runner: Runner | None = None,
        callgraph: bool = False,
    ) -> None:
        self._cfg = cfg
        # Windows 下 npm 安装的 codex 是 codex.cmd，subprocess 不解析裸名 → which 预解析
        self._codex = shutil.which(codex_path) or codex_path
        self._run = runner or _real_runner
        # callgraph=True 时把 HTTP 入口索引注入 prompt（codex exec 忽略 mcp_servers 配置）
        self._callgraph = callgraph
        self._version: str | None = None  # 缓存 --version 结果；"" 表示探测失败

    def _probe_version(self) -> str:
        """codex 版本探测与降级报错：一次探测，失败即给清晰错误（spec Further Notes）。"""
        if self._version is None:
            argv = [self._codex, "--version"]
            try:
                returncode, stdout, _ = self._run(argv, Path("."), dict(os.environ), 10.0, None)
            except Exception as e:  # noqa: BLE001
                self._version = ""
                raise RuntimeError(f"codex 版本探测失败: {e}") from e
            self._version = stdout.strip() if returncode == 0 else ""
            if returncode != 0:
                raise RuntimeError(
                    f"codex --version 退出码 {returncode}：codex 安装可能损坏"
                )
        if not self._version:
            raise RuntimeError("codex 不可用（版本探测失败）")
        return self._version

    def verify(self, candidate: Candidate, target: Path) -> Verification:
        # 相对路径 cwd/-C 会让 codex 的 .cmd shim 报 os error 3（Windows 实测），必须绝对化
        target = Path(target).resolve()
        try:
            self._probe_version()
            return self._exec(candidate, target)
        except subprocess.TimeoutExpired:
            return self._inconclusive(f"codex exec 超时（>{self._cfg.verify_timeout:g}s）")
        except FileNotFoundError:
            return self._inconclusive(
                "codex 未安装或不在 PATH：请安装 codex-cli（npm i -g @openai/codex）"
                "或用 --codex-path 指定"
            )
        except Exception as e:  # noqa: BLE001 — 验证层失败必须 fail-open 为 inconclusive
            return self._inconclusive(f"{type(e).__name__}: {e}")

    def _inconclusive(self, error: str) -> Verification:
        return Verification(
            verdict="inconclusive", cwe="", confidence="low",
            explanation="", error=error, model=self._cfg.verify_model,
        )

    def _exec(self, candidate: Candidate, target: Path) -> Verification:
        prompt = PROMPT_TEMPLATE.format(
            target=target,
            path=candidate.path,
            start_line=candidate.start_line,
            end_line=candidate.end_line,
            candidate_json=json.dumps(
                asdict_jsonable(candidate), ensure_ascii=False, indent=2
            ),
        )
        with tempfile.TemporaryDirectory(prefix="gloscope-codex-") as tmp:
            tmpdir = Path(tmp)
            codex_home = _write_codex_home(self._cfg)
            if self._callgraph:
                index = _entrypoint_index(target)
                if index:
                    prompt += (
                        "\n\nHTTP 入口索引（静态提取，file:line 可直接引用，"
                        "不必再搜索路由注册）：\n" + index
                    )
            schema_path = tmpdir / "output-schema.json"
            schema_path.write_text(
                json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            out_path = tmpdir / "final.json"
            argv = [
                self._codex, "exec",
                "--ephemeral",
                "--skip-git-repo-check",
                "--json",
                "-s", "read-only",
                "-C", str(target),
                "--output-schema", str(schema_path),
                "-o", str(out_path),
                "-c", f"model_provider={PROVIDER_ID}",
                "-m", self._cfg.verify_model,
                # prompt 走 stdin：Windows 下含引号/中文的长 prompt 经 .cmd 会被
                # cmd.exe 破坏参数边界（BatBadBut 类缺陷），且彻底消除注入面
                "-",
            ]
            env = {**os.environ, "CODEX_HOME": str(codex_home),
                   ENV_KEY: self._cfg.api_key}
            returncode, stdout, stderr = self._run(
                argv, target, env, self._cfg.verify_timeout, prompt
            )

            if returncode != 0:
                return self._inconclusive(
                    f"codex exec 退出码 {returncode}: {stderr.strip()[:500] or stdout.strip()[:500]}"
                )
            tokens_in, tokens_out = _parse_tokens(stdout)
            try:
                raw = json.loads(out_path.read_text(encoding="utf-8"))
                verdict = raw["verdict"]
                if verdict not in ("confirmed", "false_positive", "inconclusive"):
                    raise ValueError(f"非法 verdict: {verdict!r}")
            except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
                return self._inconclusive(f"验证输出不可解析: {e}")
            return Verification(
                verdict=verdict,
                cwe=str(raw.get("cwe", "")),
                taint_path=[str(s) for s in raw.get("taint_path", [])],
                confidence=raw.get("confidence", "low"),
                poc_idea=str(raw.get("poc_idea", "")),
                explanation=str(raw.get("explanation", "")),
                poc_method=str(raw.get("poc_method", "")).upper(),
                poc_path=str(raw.get("poc_path", "")),
                poc_query=str(raw.get("poc_query", "")),
                poc_body=str(raw.get("poc_body", "")),
                poc_signal=str(raw.get("poc_signal", "")),
                model=self._cfg.verify_model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )
