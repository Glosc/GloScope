# 寻幽 (GloScope)

> 大模型驱动的漏斗式漏洞审计工具，深入代码调用链寻幽探微。

本地 CLI 形态的 AI 代码漏洞扫描工具（学习/研究项目）。核心理念：静态工具擅长**找**（覆盖有保证），LLM Agent 擅长**验证和解释**（追调用链、判断可达性）——把两者焊在同一条流水线上。

## 架构

```
目标仓库 (Python Web)
   │
   ▼
① semgrep --json          候选生成（subprocess 包装，现成规则，--no-git-ignore 保证覆盖）
   │
   ▼
② LLM 分诊                keep/drop + 一行理由（便宜模型，直接 API 调用，失败 fail-open）
   │
   ▼
③ codex exec 深度验证      每个候选一个自包含 prompt（候选 JSON + 方法论 + 输出契约），
   │                       只读沙箱 + --output-schema 强制 JSON + 临时 CODEX_HOME 注入 provider
   ▼
④ 报告                     verdict 三态 / CWE / taint_path(file:line) / confidence / poc_idea
                           Markdown（人读）+ JSON（机器消费），含分层 token 成本与耗时
```

## 快速开始

```bash
# 环境：Python ≥3.11 + semgrep + codex CLI
uv venv && uv pip install -e ".[dev]"
uv pip install semgrep          # semgrep 装进同一 venv
npm i -g @openai/codex          # codex CLI

# 配置（TOML 单文件，两层共用；文件名 gloscope.toml 或 config.local.toml，后者已在 .gitignore）
cat > config.local.toml <<'EOF'
[provider]
base_url = "https://api.deepseek.com"   # 任意 OpenAI-compatible
api_key  = "sk-..."                     # 或用环境变量 GLOSCOPE_API_KEY

[models]
triage_model = "deepseek-chat"          # 分诊：便宜快
verify_model = "deepseek-reasoner"      # 验证：强模型（默认与分诊相同）
EOF

# 全漏斗扫描
gloscope scan /path/to/pygoat --config config.local.toml

# 旋钮：先小规模试跑 / 只跑部分层（semgrep-only 无需配置）
gloscope scan TARGET --max-candidates 5
gloscope scan TARGET --skip-triage --skip-verify

# 评测：固定靶场 + 四指标（召回率 / 误报数 / token 成本 / 耗时）+ 漏斗分层对比
python evals/run_eval.py --live --config config.local.toml        # tiny_app 靶场
python evals/run_eval.py --report reports/report.json             # 离线回放已有报告
gloscope eval reports/report.json --ground-truth evals/ground_truth.json
```

## 评测（开发顺序：评测先行）

每加一层，立刻看四个指标的变化（`semgrep → +triage → full` 三行即漏斗各层口径）。

当前 tiny_app 靶场（三类漏洞各一）semgrep 层实测：

| 漏斗层 | 召回率 | 误报数 | token 成本 | 耗时(s) |
|---|---|---|---|---|
| semgrep | 1.000 | 1 | 0 | 6.6 |

（误报 1 为 `debug=True` 检出——GT 外但确实是问题；分诊/验证层指标待真实 API 跑出。）

**第一条里程碑**：pygoat 上三类漏洞全部找到且误报可控（进行中）。

## 设计决策

| 决策点 | 定案 |
|---|---|
| 验证运行时 | codex（`codex exec` 运行时集成，不 fork 源码，不用 dsh） |
| 认证 | 绕开 codex 自带 OpenAI 登录；用户自填 provider（base_url + api_key），编排层生成 codex `model_providers` 配置注入，两层共用 |
| 模型分级 | 配置两个条目 `triage_model` / `verify_model`，默认相同 |
| 输出契约 | 验证层走 `--output-schema` 强制 JSON；分诊层薄输出（keep/drop + 理由） |
| 编排层语言 | Python（编排、分诊、评测一体，零第三方运行时依赖） |
| 知识注入 | 每候选自包含 exec prompt，不碰目标仓库 |
| 沙箱 | v1 只读（`codex exec -s read-only`）；动态 PoC 验证是 v2 里程碑 |
| 扫描范围 | v1 全仓（`--no-git-ignore`），目标是小靶场 |
| 失败策略 | fail-open：分诊失败保守保留、验证失败置 inconclusive，不吞候选 |
| 候选去重 | 同文件同类别 3 行内的多规则命中（django/flask 规则族重叠）合并 |

## 目标与范围

- 目标代码：Python Web（Flask / FastAPI / Django）
- 漏洞类型：SQL 注入、SSRF、路径穿越
- 靶场：内置 tiny_app（见 `evals/fixtures/tiny_app/README.md`）、pygoat、vulpy、真实 CVE 修复 commit 回放
- v2 候选：tree-sitter 自写规则补盲区、MCP 专用工具（调用图查询）、动态 PoC 执行、diff-aware 增量扫描、SARIF 输出

## 项目结构

```
gloscope/
  cli.py            # scan / eval 子命令
  config.py         # TOML 配置加载（provider + 模型分级 + 限额）
  semgrep_runner.py # 第一层：semgrep 子进程包装 + 候选解析/去重/类别推断
  triage.py         # 第二层：OpenAI 兼容分诊（keep/drop + 理由）
  verify.py         # 第三层：codex exec 包装（自包含 prompt + 输出契约 + provider 注入）
  pipeline.py       # 漏斗编排（skip 旋钮、fail-open、分层计时）
  report.py         # Markdown/JSON 报告
  metrics.py        # 四指标评测 + 漏斗分层对比
evals/
  fixtures/tiny_app/  # 靶场 payload（b64 编码存储，原因见其 README）
  ground_truth.json   # 按「文件 × 漏洞类别」标注
  run_eval.py         # 评测脚本（--live / --report）
tests/                # 全外部边界注入假实现，不依赖真实工具链
```

## 配置（TOML，单文件）

```toml
[provider]
base_url = "https://api.deepseek.com"   # 任意 OpenAI-compatible
api_key  = "sk-..."                     # 用户自填（或环境变量 GLOSCOPE_API_KEY）

[models]
triage_model = "deepseek-chat"          # 分诊：便宜快（走 chat completions）
verify_model = "deepseek-reasoner"      # 验证：强模型（默认与分诊相同；走 Responses API）

# 可选
[provider]
# wire_api 默认 "responses"——codex 0.147+ 硬性要求，网关需支持 /v1/responses 端点
[limits]
triage_timeout = 60.0                   # 分诊单次调用超时（秒）
verify_timeout = 600.0                  # codex exec 单候选超时（秒）
```

## 开发

```bash
uv pip install -e ".[dev]"
pytest                  # 64 项测试，全部离线（假 semgrep/LLM/codex）
mypy gloscope
```

需求与决策记录：`.scratch/gloscope-v1/spec.md`。
