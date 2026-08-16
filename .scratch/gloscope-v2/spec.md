# Spec: GloScope v2 — 输出格式与类别扩展

Status: ready-for-agent

上游：`.scratch/gloscope-v1/spec.md`（已实施完毕，第一里程碑达成）。
本 spec 覆盖 README 列出的 v2 候选项中最先落地的两项；其余（tree-sitter 规则、
MCP 调用图、动态 PoC、diff-aware）待本 spec 完成后另立。

## Problem Statement

v1 的报告只有 Markdown/JSON 两种自有格式，无法对接 GitHub Code Scanning、
IDE 等 SARIF 生态消费方；同时类别注册表只覆盖三类漏洞，pygoat 实测 135 个
候选中 129 个 unknown（其中 SSTI/RCE/XSS 等是真实漏洞），范围过滤后这些
真漏洞被整体排除在漏斗外。

## Solution

1. **SARIF 2.1.0 输出**：scan 在 report.md/report.json 旁再产出 report.sarif；
   confirmed → level=error，inconclusive → warning，false_positive/dropped 不入
   （非 actionable）；taint_path/poc_idea/confidence 进 result.properties。
2. **类别注册表扩展**：VULN_CATEGORIES 增加 command_injection（CWE-78）、
   xss（CWE-79）、ssti（CWE-94）；check_id 匹配片段从 pygoat 真实 semgrep
   输出归纳（数据驱动，同 v1 的 tainted-sql-string 先例）；评测口径自动跟随
   注册表（KNOWN_CATEGORIES 派生）。

## User Stories

1. As a 安全研究员, I want scan 产出 SARIF 报告, so that 结果能直接上传 GitHub Code Scanning / 被 IDE SARIF 消费方读取。
2. As a 安全研究员, I want confirmed 映射为 error、inconclusive 映射为 warning, so that 严重度排序在消费方开箱即用。
3. As a 安全研究员, I want 误报与分诊砍掉的候选不入 SARIF, so that 报告只含 actionable 项。
4. As a 安全研究员, I want taint_path/poc_idea/confidence 出现在 result.properties, so that SARIF 消费方能看到验证依据。
5. As a 安全研究员, I want 类别注册表覆盖命令注入/XSS/SSTI, so that pygoat 上的范围外真漏洞进入漏斗而非整体被过滤。
6. As a 学习者, I want 扩展类别后在 pygoat 上复测, so that 看到类别扩展对召回与成本的影响。

## Implementation Decisions

- SARIF 严格按 2.1.0 schema 的最小可用子集：runs[0].tool.driver(name/version)、
  results[](ruleId/level/message/locations/properties)；artifactLocation.uri 用
  相对路径（正斜杠）。
- 类别扩展只改 VULN_CATEGORIES 注册表（唯一事实源）；不改 metrics/semgrep_runner
  ——它们自动派生。
- 新类别 GT 以 pygoat 实际漏洞为标准（views.py 的 cmd lab、XSS lab、SSTI lab）。

## Testing Decisions

- render_sarif：固定输入 → 断言 SARIF 结构（version、level 映射、位置、properties、
  FP/dropped 排除）；CLI 测试断言 report.sarif 生成。
- 类别扩展：注册表推断单测（真实 check_id 样本 → 类别）；pygoat 真实 semgrep 输出
  回放验证。

## Out of Scope

- SARIF 的 rules 数组完整元数据（help、fullDescription）——消费方最小可用即可。
- 未知类别自动发现（unknown 仍为 unknown）。
- tree-sitter、MCP、动态 PoC、diff-aware。

## Further Notes

- v1 的 pygoat 观测（unknown keep 74 个）是本 spec 的直接动因。
- pygoat 实测补充（2026-08-16）：**SSTI 是 semgrep `auto` 规则集的盲区**，且 pygoat 的
  SSTI lab 是「用户内容写入模板文件再渲染」的间接形态——静态规则（含 tree-sitter）
  均难直接覆盖；tree-sitter 自写规则**待出现真实 `render_template_string` 靶场再启动**
  （评测先行：规则改动必须有靶场证明收益，避免自己出题自己答）。
- code_injection（CWE-94）与 deserialization（CWE-502）已随后续类别扩展落地：
  pygoat 八类范围 GT 12 项，full 1.000/0FP（3.59M token）。
- `challenge/views.py:81` 的 subprocess 候选可控性存疑，未入 GT；验证层实测判
  false_positive（container_id 来自数据库），与人工判断一致。
- **CVE 回放（2026-08-16）**：harness `evals/cve_replay.py` + 3 案例全部人工审 diff
  收录。结果 1/3 命中（redshift eval 注入 confirmed 且污点链自网络字节起）、
  3/3 修复版干净。两个 path_traversal miss 均为**候选生成层规则盲区**
  （实例属性路径/间接 ref 形态零候选）——tree-sitter 自写规则的启动条件已满足：
  GitPython/nltk 漏洞版即真实盲区靶场，CVE 回放即其评测基准。
