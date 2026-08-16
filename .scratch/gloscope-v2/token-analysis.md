# 验证层 token 去向分析（2026-08-16）

数据：`evals/token_audit.py` 对两个代表性 target 各跑一次与真实 verify 等价的
codex exec，捕获完整 `--json` 事件流。验证模型 deepseek-v4-pro。

## 原始数据

| 指标 | pygoat（Django，80 文件） | tiny_app（1 文件） |
|---|---|---|
| input tokens | 550,345 | 48,826 |
| 其中 cached | 518,528（94.2%） | 46,080（94.4%） |
| output tokens | 7,889（含 reasoning 2,903） | 1,196（含 293） |
| 工具调用次数 | 96 | 6 |
| 事件数 | 101 | 11 |

## 结构性发现

1. **turn.completed 是全会话累计值**：codex 0.147 把整个工具循环折叠为单个
   turn（96 次工具调用只有 1 条 turn.completed）——`_parse_tokens` 的累计语义
   恰好正确，无需修改。
2. **成本 ≈ 工具调用次数 × 单次往返上下文**：工具调用 96 vs 6（16 倍）对应
   input 11 倍。调用构成几乎全是 `Get-Content`（读文件内容）与 `rg`（搜索
   定义/调用点）——探索式导航是 input 膨胀的唯一驱动。
3. **缓存命中稳定在 94%**：DeepSeek 定价下缓存 input 约为 1/10 价，实际
   财务成本 ≈ 未缓存 input（约 32k）+ output（8k），单次验证的真实开销远低于
   token 总量观感。**token 量真正影响的是延迟与限流**，而非账单。
4. **首 turn 固定成本约 48k input**：即使 tiny_app 只需 6 次工具调用，也要
   48k input（codex 系统提示 + 环境注入）。小目标的成本下限即此。

## 对 MCP 调用图工具的立项结论

**有条件立项，目标修正为「省往返/延迟」而非「省 token」**：

- pygoat 的 96 次调用中，`rg`/`findstr` 类搜索（找定义、找调用点）约占
  20-30%——`resolve/callers/callees` 三工具可直接替代这部分往返；
- `Get-Content` 读文件（占大头）是语义理解，调用图救不了；
- 94% 缓存命中使「省 token」的财务意义缩水，但 96 次串行 shell 往返是
  单候选 70-90s 耗时的主要来源——**减少 20-40% 工具往返可直降延迟**；
- 实施成本低：codex `config.toml` 原生支持 `[mcp_servers.*]`，我们已掌握
  `~/.gloscope/codex-home` 注入权，stdio server（stdlib ast 实现调用图）
  即插即拔，回滚零风险。

**验收标准**：pygoat 八类评测重跑，验证层工具调用次数 -20% 以上、召回/误报
不退化；不达标即删。

## 其他降本杠杆（优先级高于 MCP）

1. **模型分级**：验证层从 v4-pro 换 v4-flash 的对比实验（pygoat 八类各跑一次）
   ——若召回不降，这是最大的单点降本/提速。
2. **tree-sitter 盲区修复**（CVE 回放已立项证据）：两个 path_traversal CVE
   零候选是召回问题，比成本问题优先。

## 附：flash 验证实验结果（2026-08-16，负结论）

pygoat 八类全漏斗，verify_model 换 deepseek-v4-flash（其余条件与 pro 基准一致）：

| | v4-pro（基准） | v4-flash（实验） |
|---|---|---|
| full 召回 | 1.000 | **0.500** |
| 误报 | 0 | 1 |
| 存疑 | 0 | **14** |
| token | 3.59M | 0.61M（-83%） |
| 耗时 | 1053s | 622s（-41%） |

14 个存疑全部为「验证输出不可解析（-o 文件为空）」——v4-flash 在
codex 0.147 + `--output-schema` 组合下无法产出合规 final message，
属环节失效而非误判。**结论：验证层必须用强模型（v4-pro），flash 只适合
分诊层**——「便宜模型分诊、强模型验证」的分级设计被数据背书。
