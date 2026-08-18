# Spec: GloScope v3 — 架构重构：codex 分叉 + Tauri 对话式桌面应用

Status: ready-for-agent

上游：`.scratch/gloscope-v2/spec.md`（v1/v2 均已实施完毕，固定 Python 流水线达成
1.000 召回/0 误报的评测基线）。本 spec 记录的不是流水线内部的功能增量，而是
产品形态的整体重构——`/grill-me` 深度访谈（39 问）确认。

## Problem Statement

v1/v2 的固定批处理流水线（semgrep → LLM 分诊 → codex exec 子进程验证 → 报告）
已经跑通并验证，但不是用户真正想要的产品形态。用户想要的是一个像 codex 一样的
**对话式桌面应用**：用户发消息说"扫描这个仓库"，AI agent 自主决定何时调用扫描/
验证工具、最终报告以聊天+本地文件形式呈现，用户可批准 AI 直接修复漏洞。

之前尝试的方向（Python 编排层 + 子进程调用 codex CLI）是规划失误。正确方向：
分叉 codex 的 Rust 源码，把 GloScope 的扫描/验证能力做成 codex 原生的
`ToolContributor` 工具，用 Tauri 2.0 + React/TypeScript 包一个桌面应用。

当前仓库无发布版本、无用户，不考虑迁移或兼容旧版本。

## Solution（决策摘要，完整执行计划见对话记录 / commit 历史）

1. **仓库重组**：`gloscope/`、`tests/`、`pyproject.toml`、`uv.lock`、旧 `README.md`
   一并 `git mv` 到 `legacy-python/`，作为不再运行、仅供端口参照的行为规范。
   `evals/` 的验证资产（tiny_app、三份 ground truth、cve_cases.json、
   cve_replay.py、run_eval.py、dogfood/quokka.md）留在根目录不动，作为新实现的
   回归验证基线；两个脚本的 `sys.path` 已改为指向 `legacy-python/`。
   `evals/token_audit.py`（深度耦合 verify.py 内部实现的一次性诊断脚本）随
   `gloscope/` 一起归档到 `legacy-python/evals/`。
2. **明确排除出 v1 端口范围**：`callgraph.py`（调用图/HTTP 入口提取）、
   `mcp_server.py`（废弃的 MCP 集成路线）、`dynamic.py`（动态 PoC 差分验证）——
   均确认无其他模块依赖，安全排除。但 `Verification` 的
   `poc_method/poc_path/poc_query/poc_body/poc_signal` 五个字段仍保留在新
   `submit_verdict` schema 里，为未来的动态验证工具预留。
3. **引入 codex 源码**：`git subtree add --prefix=codex-rs <remote> <pinned-tag>
   --squash`，硬分叉、不追踪上游，squash 成一个 commit，避免每日多次 alpha
   发布历史污染 git log。导入后建 `codex-rs/GLOSCOPE_FORK.md` 记录确切版本。
4. **Rust workspace 布局**：新工具放 `codex-rs/ext/gloscope-tools/`（与已有的
   `ext/web-search/` 同级，复用其 `ToolContributor` 实现模式）；Tauri 应用作为
   `codex-rs/` 同级目录 `gloscope-app/`，不嵌套进 Cargo workspace。
5. **里程碑**：M1 codex-rs 在 Windows 原样 build 通过 → M2 最小 Tauri 壳嵌入
   codex 跑通 passthrough 聊天 → M3 `run_semgrep` 工具端到端 + 离线测试 →
   M4a `submit_verdict` 工具 / M4b 多候选子任务扇出编排（最大不确定性，需专项
   探索）→ M5 `triage` 工具（可选） → M6a git 审计分支安全机制 / M6b
   `apply_patch` 修复流程接线 → M7 首次引导向导 + keyring 凭据存储 →
   M8 CI + Inno Setup 打包 + minisign 自动更新。
6. **域知识移植**：`VULN_CATEGORIES` CWE 表、`Candidate`/`Verification` 结构、
   `submit_verdict` 12 字段契约（含"空字符串=不适用"扁平化技巧）、验证方法论
   prompt——均为机械搬迁，非重新设计；三个枚举字段 Python `Literal` → Rust
   enum 是白得的类型安全提升。
7. **回归验证策略**：`run_eval.py`/`metrics.py::evaluate()`/
   `report.py::report_from_json()` 不需要 Rust 重写，只要新 Rust 工具产出的
   `findings.json` 内容匹配现有 `render_json()` 字段形状（必要时写薄
   adapter）。验证闸门：M4 完成后跑 tiny_app 全链路对比历史基线；M5 后复核
   `+triage`；M8 打包前跑全套（pygoat 两版、vulpy、CVE 回放）。`cve_replay.py`
   当前依赖 Python CLI 触发扫描，v1 产品是纯 GUI 无 CLI 入口——这是一个留到
   M6 后单独确认的开放问题（保留最小自动化入口 vs. 重写扫描触发部分）。

## Out of Scope（v1 明确不做）

调用图辅助工具、动态 PoC 差分工具、`--diff-base` 增量扫描、多项目/会话历史
管理、持久化聊天记录、代码签名、遥测、i18n 翻译（仅骨架）。

## 关键文件

- `legacy-python/gloscope/verify.py` — submit_verdict 的 schema/prompt/严格化
  技巧来源
- `legacy-python/gloscope/semgrep_runner.py` — run_semgrep 的子进程包装/去重/
  过滤逻辑来源
- `legacy-python/gloscope/models.py` — CWE 表和核心 dataclass 来源
- `legacy-python/gloscope/report.py` — 必须保持兼容（或适配）的 JSON 契约
- `evals/run_eval.py`、`evals/cve_replay.py` — 回归验证入口
