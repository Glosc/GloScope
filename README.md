# 寻幽 (GloScope)

> AI 驱动的对话式代码漏洞审计桌面应用。

GloScope 正在从一个固定批处理的 Python CLI 流水线，重构为一个基于 [codex](https://github.com/openai/codex)（Rust）分叉的对话式桌面应用：用户在聊天界面里说"扫描这个仓库"，AI agent 自主决定何时调用传统扫描工具（semgrep）、何时做深度验证、何时生成报告，最终由用户决定是否让 AI 直接修复漏洞。

这次重构的完整背景、决策记录和执行计划见 `.scratch/gloscope-v3/`（新增，记录本次架构重构的访谈决策）与本仓库根目录下的迁移说明（见下）。

## 当前状态（重构中）

- **`legacy-python/`** — 之前完全跑通的 Python 实现（semgrep → LLM 分诊 → codex exec 子进程验证 → Markdown/JSON/SARIF 报告），118 个测试全绿，在 tiny_app/pygoat/vulpy/CVE 回放上都验证过（1.000 召回率、0 误报）。**不再作为产品运行**，仅作为新 Rust 实现的行为规范参照——域知识（CWE 分类表、验证方法论 prompt、输出契约）会被移植过去，架构本身不会。详见 `legacy-python/README.md`（原 README，完整记录了旧架构的设计决策与评测数据）。
- **`evals/`** — 回归验证资产（tiny_app 靶场、ground truth 标注、CVE 回放案例）保留在根目录，作为新 Rust 实现完成后的回归验证基线，不会随旧代码一起归档。
- **codex 分叉（`codex-rs/`）与 Tauri 桌面应用（`gloscope-app/`）** — 尚未引入，是本次重构的下一步。

## 目标架构

```
用户聊天输入（"扫描这个仓库"）
        │
        ▼
codex agent（原生 tool-calling，非固定流水线）
        │
        ├─ run_semgrep      候选生成工具（端口自 legacy-python/gloscope/semgrep_runner.py）
        ├─ triage           可选分诊工具（AI 自主决定是否调用）
        └─ submit_verdict   结构化验证结论工具（端口自 legacy-python/gloscope/verify.py 的
                             12 字段契约：verdict/cwe/taint_path/confidence/poc_idea/
                             explanation/execution_context + poc_* 动态验证字段）
        │
        ▼
聊天窗口摘要 + 本地报告文件（<目标仓库>/.gloscope/scans/<timestamp>/findings.json + report.md）
        │
        ▼
用户批准后，AI 用 codex 自带的 apply_patch 工具修复，落在新建的审计分支上
```

技术栈：Rust（codex 分叉核心 + 新工具）+ Tauri 2.0 + React/TypeScript（桌面前端）。

## 开发

重构执行计划见 `.scratch/gloscope-v3/spec.md`（如尚未创建，参见对话记录中的里程碑 M1–M8）。旧 Python 实现的开发方式见 `legacy-python/README.md` 的"开发"章节。
