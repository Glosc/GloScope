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
                           Markdown + JSON + SARIF（机器消费），含分层 token 成本与耗时
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

# 旋钮：先小规模试跑 / 只跑部分层（semgrep-only 无需配置）/ 限定漏洞类别 / 增量扫描
gloscope scan TARGET --max-candidates 5
gloscope scan TARGET --skip-triage --skip-verify
gloscope scan TARGET --categories sql_injection,ssrf,path_traversal
gloscope scan TARGET --diff-base origin/main        # CI 里只扫 PR 变更文件

# 评测：固定靶场 + 四指标（召回率 / 误报数 / token 成本 / 耗时）+ 漏斗分层对比
python evals/run_eval.py --live --config config.local.toml        # tiny_app 靶场
python evals/run_eval.py --report reports/report.json             # 离线回放已有报告
gloscope eval reports/report.json --ground-truth evals/ground_truth.json
```

## 评测（开发顺序：评测先行）

每加一层，立刻看四个指标的变化（`semgrep → +triage → full` 三行即漏斗各层口径）。

tiny_app 靶场（三类漏洞各一）**全漏斗真实运行**结果（DeepSeek v4-flash 分诊 + v4-pro 验证，2026-08-16）：

| 漏斗层 | 召回率 | 误报数 | token 成本 | 耗时(s) |
|---|---|---|---|---|
| semgrep | 1.000 | 1 | 0 | 6.7 |
| +triage | 1.000 | 0 | 2,165 | 14.7 |
| full | 1.000 | 0 | 424,593 | 154.0 |

要点：
- 三类漏洞全部 `confirmed`（high 置信、完整 file:line 污点链、可执行 PoC）；唯一 GT 外候选（`debug=True`）被分诊/验证层正确清除——漏斗的价值直接可读。
- **验证层是成本大头**（codex agent 多轮工具调用，单候选平均 ~10 万 token，其中大部分可命中缓存）；先用 `--max-candidates` 小规模试跑，分诊模型选便宜的。

### pygoat（第一里程碑 + v2 类别扩展）

大靶场 pygoat（Django，80 个 Python 文件，135 个 semgrep 候选）。v2 起类别注册表扩展到六类（新增 命令注入 CWE-78、XSS CWE-79、SSTI CWE-1336），GT 7 项：

| 漏斗层 | 召回率 | 误报数 | token 成本 | 耗时(s) |
|---|---|---|---|---|
| semgrep | 1.000 | 1 | 0 | 10.6 |
| +triage | 1.000 | 1 | 8,185 | 48.8 |
| full | **1.000** | **0** | 3,342,950 | 844.1 |

v1 三类范围（6 候选）：full 1.000/0FP，1.52M token / 414s——污点链自 Django 路由注册追到 sink。

**v2 八类范围（22 候选，GT 12 项）：full 1.000 / 0FP，3.59M token / 1053s。** 新增类别 code_injection（CWE-94，`eval()` 用户输入）与 deserialization（CWE-502，pickle cookie / `yaml.load` 上传文件）全部命中，且再次展示判别力：`pickle.dumps`（服务器侧构造，非漏洞）被分诊砍、`challenge/views.py:81`（数据库来源参数）被验证层判 FP。v2 六类中间结果（14 候选/GT 7 项）同为 1.000/0FP（3.34M token）。

已知盲区（记录于 `.scratch/gloscope-v2/spec.md`）：**SSTI 在 semgrep `auto` 规则集下零候选**（tree-sitter 自写规则的直接依据）；`eval()` 代码注入（CWE-94）与反序列化（CWE-502）类别留待后续扩展。

全量分诊观测（135 候选不过滤）：keep 80 / drop 55（**砍削 40%**，94k token / 439s）。

### CVE 回放（真实世界代码，v2 新增）

`evals/cve_replay.py`：浅取 CVE 修复 commit（`--depth 2`）→ 漏洞版/修复版双向验证（案例均经人工审 diff 收录，见 `evals/cve_cases.json`）。**自写盲区规则接入后**（v2 第二轮）：

| CVE | 项目 | 类别 | 漏洞版命中 | 修复版干净 |
|---|---|---|---|---|
| CVE-2026-8838 | aws redshift-connector | code_injection | ✅（污点链自服务端网络字节追到 `eval`） | ✅（零候选） |
| CVE-2026-12243 | nltk | path_traversal | ✅（自写规则 `open(self.$ATTR)` 命中） | ✅（零候选） |
| CVE-2023-41040 | GitPython | path_traversal | ✅（自写规则 join+str 形态命中） | ❌＝**正确发现**：验证层指出 `..` 子串检查可被绝对路径绕过（`os.path.join` 二参以 `/` 开头），与上游 PR #1644 确认、3.1.37 补强的事实吻合 |

**自写盲区规则**（`gloscope/rules/blindspots.yml`，默认与 `--config auto` 并联）：semgrep auto 实测在「实例属性路径 `open(self._path)`」与「join+str() 拼接路径」两类真实穿越形态上零候选——两条窄化 YAML 规则补齐，pygoat 全仓 FP 增量为 0。原计划的 tree-sitter 由此**由自写 semgrep 规则替代**（同样达成「自写规则补盲区」，零新依赖）。

### 验证层 token 去向（v2 实测，分析见 `.scratch/gloscope-v2/token-analysis.md`）

| | pygoat（大仓库） | tiny_app |
|---|---|---|
| input（cached 占比） | 550k（**94%**） | 49k（94%） |
| output | 7.9k | 1.2k |
| 工具调用次数 | **96** | 6 |

成本 ∝ 工具调用次数（读文件/搜索的探索式导航）；94% 缓存命中使真实账单远低于 token 观感，token 量主要影响延迟。**flash 验证实验（负结论）**：verify_model 换 v4-flash 后召回 0.500（14 个存疑均为输出环节失效）、token -83%——验证层必须用强模型，分级设计被数据背书。

**调用图辅助（v2 落地）**：原 MCP 工具方案实测被 codex exec 静默忽略（`[mcp_servers]` 仅 TUI 生效，server 协议测试全过、模块保留备用），退化为 **HTTP 入口索引注入 prompt**（`gloscope/callgraph.py` 静态提取 Flask/Django 路由，`--no-callgraph` 可关）。单候选控制变量对比：工具调用 **96 → 21（-78%）**、input -47%，召回保持；pygoat 八类全量召回/误报不退化（全量 token/耗时受运行随机性主导，省耗结论仅在控制变量下成立）。详见 `.scratch/gloscope-v2/token-analysis.md`。

### 动态 PoC 复现（v2 落地）

验证层输出契约新增声明式 PoC 请求规格（`poc_method/path/query/body/signal` 扁平字段），`gloscope check-dynamic <report.json> --target-url <环回地址>` 用自带 HTTP 客户端做**差分复现**（PoC 请求 vs 基线请求的信号对比）。安全边界：PoC 是请求规格而非可执行代码；目标硬编码环回白名单（127.0.0.1/::1/localhost，localhost 需 DNS 全环回）、仅 http/https、禁跨域重定向；必须显式传 `--target-url`。范围（用户批准）：v1 仅 tiny_app/vulpy（Flask，用户手动启动），pygoat 保持静态。

tiny_app 实测（agent 生成的 PoC 规格直接可用）：**2/3 动态复现**——SQL 注入（`id=' OR '1'='1` → 响应含 `"admin"`）与路径穿越（`name=../../app.py` → 响应含源码标记）差分成立；SSRF 未复现属 agent 信号设计与靶场 error 页不匹配（执行器行为正确）。执行器实测修复两项：未编码空格的百分号编码、预编码串的双重编码防护。

### vulpy（第三靶场，Flask/SQLite）

vulpy 的 `bad/`（漏洞版）与 `good/`（安全版）同名对照是天然的误报考验——semgrep 在两边都会报格式相似的 sink：

| 漏斗层 | 召回率 | 误报数 | token 成本 | 耗时(s) |
|---|---|---|---|---|
| semgrep | 1.000 | 3 | 0 | 8.1 |
| +triage | 1.000 | 3 | 2,798 | 20.1 |
| full | **1.000** | **0** | 932,292 | 294.9 |

验证层的判别力实录：3 个 confirmed（`bad/libuser.py` 登录/创建/改密，`request.form` 用户可控）；3 个 false_positive 各有正确理由——`bad/db*.py` 的拼接输入是**硬编码初始化数据**（非用户输入），`good/libuser.py:61` 是安全对照版（追调用链后发现无可达污点链）。**good/ 上的候选被正确清除，对照考验通过。**

**第一条里程碑：✅ pygoat 上三类漏洞全部找到（召回 1.000）且误报可控（0）；v2 扩展到六类后 pygoat/vulpy 均保持 1.000/0。**

### Dogfood：真实 CMS 项目（Quokka，2026-08-18）

第一次在无 ground truth 的真实项目上全流程运行（`evals/dogfood/quokka.md`），暴露出上述受控靶场未覆盖的问题：

| 层 | 候选数 | keep/drop | 确认 | 误报 | 存疑 | token 成本 | 耗时(s) |
|---|---|---|---|---|---|---|---|
| semgrep | 108 | — | — | — | — | 0 | 30.7 |
| +triage | 108 | 27 kept / 81 dropped | — | — | — | 166k | 388.7 |
| full | 108 | — | 2 | 23 | 2 | 21.35M | 4879.2 |

发现 1 个真实 Stored XSS（CWE-79，`Orderable.__html__` 绕过 Jinja 自动转义，PoC 可直接构造）与 1 个客户端 ReDoS 边界案例。验证层对 27 个 kept 候选的判别力人工复核全部正确。

**暴露的四个问题已修复**：
1. semgrep 误匹配 vendored JS（108 候选中 ~70 来自前端静态库）→ 默认模式加 `--include "*.py"`（`paths` 模式不受影响，尊重用户显式清单）
2. codex 偶发空输出（`Expecting value: line 1 column 1`）→ 自动重试一次
3. 类别注册表覆盖不足（`unknown` 候选里验证层推断出 CWE-1333/CWE-706 但注册表没有对应类别）→ 新增 `regex_dos`（CWE-1333）、`improper_check`（CWE-706）
4. 服务端/客户端边界不明确（tipuesearch.js 的 ReDoS 是客户端代码，风险等级与服务端漏洞不同）→ 验证层输出新增 `execution_context: server | client | unknown` 字段

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
| 扫描范围 | v1 全仓（`--no-git-ignore`），目标是小靶场；dogfood 后默认加 `--include "*.py"`（`paths` 模式不受影响） |
| 失败策略 | fail-open：分诊失败保守保留、验证失败置 inconclusive，不吞候选 |
| 候选去重 | 同文件同类别 3 行内的多规则命中（django/flask 规则族重叠）合并 |

## 目标与范围

- 目标代码：Python Web（Flask / FastAPI / Django）
- 漏洞类型：SQL 注入、SSRF、路径穿越、命令注入、XSS、代码注入（CWE-94）、反序列化（CWE-502）、ReDoS（CWE-1333）、不恰当校验（CWE-706，dogfood 新增两类）；SSTI 已入注册表待规则补盲区（pygoat 的 SSTI 为文件写入型，静态规则难覆盖，待真实 `render_template_string` 靶场）
- 报告格式：Markdown / JSON / **SARIF 2.1.0**（v2 新增，confirmed→error / inconclusive→warning，可直接上传 GitHub Code Scanning）
- 靶场：内置 tiny_app（见 `evals/fixtures/tiny_app/README.md`）、pygoat（GT 7 项）、vulpy（GT 1 项，good/bad 对照）、真实 CVE 修复 commit 回放、真实 CMS 项目 dogfood（Quokka，无 ground truth）
- v2 已落地：SARIF 输出、类别注册表扩展（3→8 类，dogfood 后再扩至 10 类）、vulpy 靶场、diff-aware 增量扫描（`--diff-base`，git diff 变更文件过滤，拿不到 diff 即报错不盲目全仓）、CVE 回放、自写盲区规则（`gloscope/rules/`）、调用图入口索引注入（`--no-callgraph` 可关）、动态 PoC 复现（`check-dynamic`，环回白名单）、验证层执行上下文标注（`execution_context: server | client | unknown`）、semgrep 默认限定 `--include "*.py"`（dogfood 实测 vendored JS 误匹配占比过高）

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
pytest                  # 118 项测试，全部离线（假 semgrep/LLM/codex）
mypy gloscope
```

需求与决策记录：`.scratch/gloscope-v1/spec.md`。
