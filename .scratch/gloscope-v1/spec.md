# Spec: GloScope v1 — 漏斗式漏洞审计流水线

Status: ready-for-agent

## Problem Statement

安全研究员/学习者扫描 Python Web 靶场（pygoat、vulpy、CVE 回放）时面临两难：

- 纯静态工具（semgrep 等）**找得全但误报多**——它只做模式匹配，无法判断污点是否真的可达 sink，结果里混大量噪音，人工逐条复核成本高。
- 纯 LLM 全仓审计**会验证但覆盖无保证**——token 成本随仓库体积爆炸，且没有系统性保证「该看的代码都看过了」。

用户需要把两者焊在同一条流水线上：静态工具负责**找**（覆盖有保证），LLM Agent 负责**验证和解释**（追调用链、判断可达性），并用固定靶场上的量化指标（召回率、误报数、token 成本、耗时）证明每层的价值。

## Solution

本地 CLI 工具 `gloscope`，一条命令对目标仓库跑四段漏斗：

1. **候选生成**：包装 `semgrep --json`，用现成规则把目标仓库里的 SQL 注入 / SSRF / 路径穿越候选全部找出来。
2. **LLM 分诊**：便宜模型通过直接 OpenAI-compatible API 调用对每个候选做 keep/drop 判断 + 一行理由，砍掉明显误报。
3. **深度验证**：对每个 keep 的候选，组装自包含 prompt（候选 JSON + 方法论 + 输出契约），交 `codex exec` 在只读沙箱里自追污点链，`--output-schema` 强制结构化 JSON 输出。
4. **报告**：verdict 三态 / CWE / taint_path(file:line) / confidence / poc_idea，Markdown 人读 + JSON 机器消费。

配套**评测脚本**：固定靶场 + ground truth 标注，输出召回率、误报数、token 成本、耗时四个指标，可分层对比（仅 semgrep / +分诊 / 全流水线）。

认证与模型：用户在 TOML 单文件自填 provider（base_url + api_key，任意 OpenAI 兼容服务）；编排层生成 codex `model_providers` 配置注入，分诊/验证两层共用；`triage_model` / `verify_model` 两个条目，默认相同。

## User Stories

1. As a 安全研究员, I want 用一条 CLI 命令 `gloscope scan <target>` 扫描整个 Python Web 仓库, so that 不需要了解内部机制就能拿到漏洞报告。
2. As a 安全研究员, I want 第一层用 semgrep 现成规则跑全仓生成候选, so that 覆盖有保证、已知模式不遗漏。
3. As a 安全研究员, I want 第二层用便宜 LLM 对每个候选输出 keep/drop + 一行理由, so that 昂贵的深度验证只花在值得的候选上。
4. As a 安全研究员, I want 第三层 codex exec 拿到自包含 prompt（候选 JSON + 方法论 + 输出契约）, so that 验证 agent 不需要额外上下文就能自追污点链。
5. As a 安全研究员, I want 验证层用 `--output-schema` 强制 JSON 输出, so that 模型自由发挥不会炸掉解析层。
6. As a 安全研究员, I want 验证结论包含 verdict 三态（confirmed / false_positive / inconclusive）, so that 人工复核可以按优先级分流。
7. As a 安全研究员, I want 验证结论包含 CWE 编号, so that 报告能对接漏洞分类习惯和后续统计。
8. As a 安全研究员, I want 验证结论包含 taint_path 且每步是 file:line, so that IDE 能直接跳转复核污点链。
9. As a 安全研究员, I want 验证结论包含 confidence（high/medium/low）和 poc_idea, so that 高置信度发现可以直接进入利用验证，低置信度进人工队列。
10. As a 安全研究员, I want 分诊/验证两层在只读沙箱运行, so that 扫描过程绝不修改目标仓库。
11. As a 安全研究员, I want 在 TOML 单文件里配置 provider base_url + api_key, so that 任意 OpenAI 兼容服务（DeepSeek 等）都能用。
12. As a 安全研究员, I want 编排层自动生成 codex `model_providers` 配置注入, so that 绕开 codex 自带 OpenAI 登录、两层共用凭据。
13. As a 安全研究员, I want 配置里 `triage_model` / `verify_model` 分开指定（默认相同）, so that 分诊用便宜快模型、验证用强模型。
14. As a 安全研究员, I want 任一层执行出错或超时的候选被保守保留并标记 error, so that 基础设施抖动不吞掉真阳性。
15. As a 安全研究员, I want 报告同时输出 Markdown 和 JSON, so that 人读和脚本消费都有。
16. As a 安全研究员, I want 每个候选带分层轨迹（kept/dropped-at-triage/verified/error）, so that 漏斗哪里砍掉了什么一目了然，可调试。
17. As a 安全研究员, I want `--max-candidates`、`--skip-triage`、`--skip-verify` 这类旋钮, so that 先小规模试跑控制成本。
18. As a 安全研究员, I want semgrep / codex 未安装或版本不对时得到清晰报错, so that 环境问题能快速自修。
19. As a 安全研究员, I want token 成本按层（分诊/验证）统计, so that 模型选型有数据依据。
20. As a 学习者, I want 评测脚本在固定靶场输出召回率、误报数、token 成本、耗时, so that 每加一层立刻看到指标变化。
21. As a 学习者, I want 评测能分层对比（仅 semgrep / semgrep+分诊 / 全流水线）, so that 理解漏斗每一层的价值。
22. As a 学习者, I want 靶场和 ground truth 固定在仓库里, so that 评测可复现、指标可跨版本比较。
23. As a 学习者, I want 第一里程碑是 pygoat 上三类漏洞全部找到且误报可控, so that 端到端价值被证明后再谈扩展。

## Implementation Decisions

- **包名与语言**：Python ≥ 3.11，包名 `gloscope`（对齐 README 与仓库名；原 pyproject 的 `whitehatgpt` 是旧脚手架名，废弃），CLI 入口 `gloscope`。
- **模块划分**（每个模块一个清晰边界，外部依赖只出现在边界内）：
  - `config`：TOML 加载 + 校验（provider.base_url/api_key、models.triage_model/verify_model），api_key 支持 `GLOSCOPE_API_KEY` 环境变量回退。发现顺序：--config 显式路径 → `GLOSCOPE_CONFIG` → `./gloscope.toml` → `./config.local.toml`。
  - `candidates` → 实现拆为 `models`（候选/结论数据模型 + 漏洞类别注册表 VULN_CATEGORIES 唯一事实源）与 `semgrep_runner`（subprocess 包装 + JSON 解析）。
  - `triage`：OpenAI-compatible chat completions 直接 HTTP 调用，输出 keep/drop + 理由 + token usage。
  - `verify`：codex exec 子进程封装——版本探测（实例级缓存，失败降级报错）、生成临时 `CODEX_HOME`（写入 `model_providers` 注入用户 provider）、组装自包含 prompt、`--output-schema` 强制 JSON、只读沙箱参数、解析最终事件流拿结构化结论。
  - `report`：候选全量 + 各层判定 → Markdown 报告与 JSON 报告（含分层统计与 token 成本）。
  - `pipeline`：编排四段漏斗 + 分层计时与指标聚合，所有外部边界（semgrep、LLM、codex）以可注入接口存在。
  - `cli`：argparse 子命令 `scan` / `eval`。
  - `evals/`：固定靶场 fixture + ground truth 标注 + 评测脚本（四指标输出、分层对比）。
- **候选去重与覆盖**（真实冒烟后新增的决策）：semgrep 以 `--no-git-ignore` 扫描（审计要覆盖保证）；同文件同类别 3 行内的多规则命中（p/flask 与 p/django 规则族重叠）合并为一个候选；registry metadata CWE 错挂时（如 tainted-sql-string → CWE-704）以规则族推断为准。
- **验证输出契约**（JSON schema 核心字段）：`verdict` ∈ {confirmed, false_positive, inconclusive}；`cwe`（如 CWE-89）；`taint_path` 为 file:line 步骤数组；`confidence` ∈ {high, medium, low}；`poc_idea`；`explanation`。
- **分诊输出契约**：薄输出——`keep`（bool）+ `reason`（一行）。
- **codex 集成方式**：不 fork 源码、不引 SDK，`codex exec` 子进程 + 临时配置注入；具体 flag 组合以本机 `codex exec --help` 实测为准，spec 只锁定「自包含 prompt + 结构化输出 + 只读沙箱」三个不变量。
- **失败策略**：fail-open——分诊调用失败按 keep 处理；验证失败/超时输出 inconclusive + error 轨迹（Finding.status 为 `error`）；semgrep 失败直接终止本次扫描（无候选则无意义）。
- **评测口径**：ground truth 按「文件 × 漏洞类别」标注；recall = 被 confirmed 的 ground truth 项 / 全部项；误报数 = confirmed 但不在 ground truth 的候选数；token 成本按层累计 usage；耗时按层计时（漏斗各行为到该层为止的累计值）。靶场 v1 以 vendored 小 fixture 起步（pygoat 作为可选外部靶场），保证评测离线可跑。

## Testing Decisions

- **最高接缝 = pipeline 编排层**：端到端测试注入 fake semgrep（返回录制 JSON）、fake LLM（脚本化应答）、fake codex（stub 可执行/可调用对象），断言报告内容与四指标——不依赖任何真实工具链即可全量回归。
- semgrep JSON 解析：用录制的真实 semgrep 输出 fixture 单测（含空结果、多候选、异常行号）。
- triage/verify：单测 prompt 组装与输出契约校验（好 JSON、坏 JSON、超时、非零退出码）。
- codex 配置注入：断言生成的临时 config.toml 内容正确、环境隔离。
- report：golden 快照断言 Markdown/JSON 结构。
- 只测边界行为（给定输入 → 报告/指标/退出码），不测子进程内部实现细节。
- 新仓库无先例测试，本 spec 的测试构成 prior art：fixture 驱动 + fake 边界注入。

## Out of Scope

- v2 里程碑项：tree-sitter 自写规则补盲区、MCP 专用工具（调用图查询）、动态 PoC 执行、diff-aware 增量扫描、SARIF 输出。
- 非 Python Web（Flask/FastAPI/Django 之外）目标语言支持。
- 并行/分布式扫描调度（v1 串行逐候选验证）。
- Web UI / 服务化形态。
- 真实 CVE commit 回放评测（v1 只留接口，靶场用 vendored fixture + 可选 pygoat）。

## Further Notes

- README 是本 spec 的唯一上游输入；实现过程中与 README 冲突时以本 spec 为准并回写 README。
- codex CLI 版本差异（`--output-schema`、事件流格式）是主要环境风险，verify 模块需带版本探测与降级报错。
- 命名漂移：仓库内曾出现 `whitehatgpt`（旧脚手架空目录 + pyproject 名），统一清理为 `gloscope`。
