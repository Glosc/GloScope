# Dogfood: Quokka CMS

## 目标元信息

| 项 | 值 |
|---|---|
| 仓库 | https://github.com/quokkaproject/quokka |
| 扫描 commit | a4d5cb6528d69b79f5e0d87a1faae70e84a3ec51 (Initial commit) |
| 框架 | Flask (Flask-Admin + MongoEngine) |
| Python LOC | 5,461 (54 文件) |
| 扫描日期 | 2026-08-18 |

## 漏斗指标

| 层 | 候选数 | keep/drop | 确认 | 误报 | 存疑 | 错误 | token 成本 | 耗时(s) |
|---|---|---|---|---|---|---|---|---|
| semgrep | 108 | — | — | — | — | — | 0 | 30.7 |
| +triage | 108 | 27 kept / 81 dropped (75%) | — | — | — | — | 166k | 388.7 |
| full | 108 | — | 2 | 23 | 2 | 2 | 21.35M | 4879.2 |

> 分诊层削减 75% 候选，显著降低验证成本。验证层对 27 个 kept 候选给出 2 confirmed / 23 FP / 2 inconclusive / 2 error。

## 人工判定

对 gloscope 输出的 27 个 verified 候选逐条人工复核：

| # | file:line | 类别 | gloscope verdict | 人工判定 | 说明 |
|---|---|---|---|---|---|
| 1 | quokka/admin/actions.py:90 | xss | false_positive | ✅ TP (FP 判定合理) | Markup(user[username]) sink 真实，但 username 仅由 CLI adduser 或受 SimpleLogin 保护的管理员表单创建，不可被外部未认证用户控制。FP 判定正确 |
| 2 | quokka/admin/actions.py:151 | xss | inconclusive | ✅ FP (与 #1 同源) | codex 输出解析失败（偶发），实际应为与 #1 同模式的 FP |
| 3 | quokka/cli.py:182 | code_injection | false_positive | ✅ FP | eval(line) 的 line 来自 Click CLI 子命令参数，无 HTTP 路由可达，属本地命令执行 |
| 4 | quokka/core/blueprints.py:43 | unknown | false_positive | ✅ FP | import_module 的 module_name 来自 os.listdir() 本地目录扫描，非 HTTP 可控 |
| 5 | quokka/core/blueprints.py:50 | unknown | false_positive | ✅ FP | 同 #4，admin 模块导入路径完全由本地目录结构决定 |
| 6 | quokka/core/commands_collector.py:47 | unknown | false_positive | ✅ FP | module 来自 Click 命令行子命令名，未注册到任何 HTTP 路由 |
| 7 | quokka/core/content/formats.py:407 | xss | inconclusive | ⚠️ 需复核 | Markup(markdown(content))——content 来源需追 CMS 内容管理流程，codex 解析失败 |
| 8 | **quokka/core/content/models.py:50** | **xss** | **confirmed** | **✅ TP** | **Orderable.__html__ 返回 str(self)，绕过 Jinja 自动转义；author/category/tag 路由的 URL 路径参数完全用户可控，直接传入模板渲染。完整 source→sink 链确认** |
| 9 | quokka/core/content/models.py:369 | xss | false_positive | ✅ FP | Content.__html__ 同模式，但 Content.__str__ 返回 self.title，title 来源是管理员编辑，不跨信任边界 |
| 10 | quokka/core/content/models.py:468 | unknown | false_positive | ✅ FP | globals().get() 动态模型实例化，model_name 由 content_type 内部拼接+capitalize，不可外部控制 |
| 12 | quokka/core/flask_dynaconf.py:112 | xss | false_positive | ✅ FP | Markup(v) 的 v 来自应用启动时配置文件，非运行时 HTTP 输入 |
| 13 | themes/Flex/.../article.html:33 | unknown | false_positive | ✅ FP | 第三方 JS（Google AdSense）缺少 SRI，非性能安全漏洞 |
| 28 | themes/bootstrap3/tipuesearch.js:205 | unknown | false_positive | ✅ FP | 客户端 RegExp，q 参数在浏览器端执行，非服务端 ReDoS |
| 29 | themes/bootstrap3/tipuesearch.js:221 | unknown | false_positive | ✅ FP | 同 #28，客户端正则，不跨服务端信任边界 |
| 30 | themes/bootstrap3/tipuesearch.js:225 | unknown | false_positive | ✅ FP | 同 #28 |
| 31 | **themes/bootstrap3/tipuesearch.js:254** | **unknown** | **confirmed** | **⚠️ 边界案例** | **客户端 ReDoS（CWE-1333）：q 参数经 toLowerCase/trim/分词后直接 new RegExp，恶意嵌套量词可指数级回溯。但 bootstrap3 是非默认主题（默认 malt），且是 vendored 第三方插件。工具行为正确（确认了真实缺陷），但实际风险取决于部署配置** |
| 32 | themes/bootstrap3/tipuesearch.js:281 | unknown | false_positive | ✅ FP | 同 #28，vendored 客户端代码 |
| 33 | themes/bootstrap3/tipuesearch.js:297 | unknown | false_positive | ✅ FP | highlight 功能默认未启用 |
| 34 | themes/bootstrap3/tipuesearch.js:301 | unknown | false_positive | ✅ FP | highlight 功能默认未启用 |
| 42 | themes/clean/clean-blog.js:955 | unknown | false_positive | ✅ FP | 前端表单验证正则，inputstring 来自用户输入但在浏览器端，非服务端 |
| 67-82 | themes/octopress/ender.js 等 | unknown | false_positive | ✅ FP (批量) | vendored 第三方前端库（ender/qwery/reqwest/twitter），动态 RegExp/eval 均在浏览器端执行，无服务端可达路径 |

## 漏洞发现清单

| # | CWE | 严重度 | 位置 | 描述 | gloscope 置信度 |
|---|---|---|---|---|---|
| 1 | CWE-79 | Medium | quokka/core/content/models.py:50 | **Stored XSS via Orderable.__html__**：author/category/tag 路由的 URL 路径参数经 `__html__` → `str(self)` → `__str__` 链直接输出，绕过 Jinja 自动转义。PoC: `GET /author/<script>alert(1)</script>/` | high |
| 2 | CWE-1333 | Low | themes/bootstrap3/tipuesearch.js:254 | **客户端 ReDoS**：搜索词 q 经分词后直接传入 `new RegExp`，恶意嵌套量词可导致浏览器无响应。仅 bootstrap3 主题（非默认）生效，属 vendored 第三方插件缺陷 | medium |

## 经验总结

### 工具做对了什么

1. **分诊层砍削高效**：108 → 27（75% drop rate），81 个 dropped 候选主要是 HTML 模板中的 vendored JS 库模式匹配（semgrep 对 JS 也产生了大量匹配）
2. **验证层判别力强**：27 个 kept 中 23 个 FP 判定全部正确——每个都有完整的污点链分析，准确识别了「sink 真实但 source 不可达」的模式（CLI-only、admin-only、startup-only、vendored JS）
3. **真实漏洞发现**：#8 的 XSS 有完整的 source→sink 链追踪（URL path → Category(category) → Category.__str__ → Orderable.__html__ → 模板 {{ category }}），PoC 直接可用
4. **调用图入口索引生效**：验证层正确引用了 Flask 路由入口（`/<path:category>/`、`/author/<path:author>/`），帮助排除无 HTTP 可达路径的 CLI 代码

### 暴露的问题

1. **semgrep 对 JS 误匹配过多**：108 个候选中 100 个是 `unknown` 类别，绝大多数是 vendored JS 库中的 `new RegExp`/`eval`/`document.write`。GloScope 的 `--no-git-ignore` 扫描了 project_template 下的第三方前端资源。**改进方向**：可考虑按文件扩展名过滤（仅扫 `.py`），或在分诊层增加「非 Python 文件直接 drop」的快速路径
2. **类别推断局限**：100 个 `unknown` 类别中验证层推断出了 CWE-1333（ReDoS）、CWE-706（不恰当校验）、CWE-96（JSON 中的 SSRF）等，但这些语义类别不在 `VULN_CATEGORIES` 注册表内。**改进方向**：扩展注册表或在报告中对 non-canonical 类别做标注
3. **偶发 codex 输出解析失败**：2 个 inconclusive 均因 `Expecting value: line 1 column 1`（codex 返回空响应）。**改进方向**：对空输出自动重试一次
4. **客户端 vs 服务端边界模糊**：tipuesearch.js 的 ReDoS 被正确识别为真实缺陷，但服务端 vs 客户端的区分在报告中不明确。**改进方向**：验证层输出增加 `execution_context: server | client` 字段

### 漏掉了什么

- **`Markup(markdown(content))`（#7）**：content 来源是 CMS 内容管理流程，需要追踪文章创建/编辑流程中是否有 HTML 净化。codex 解析失败导致该候选未被充分分析——可能是另一个真实 XSS
- **Semgrep 自身在 Python 文件上的覆盖**：Quokka 的 `send_from_directory` 路由（`/theme/<path:filename>`）存在路径穿越风险，但 semgrep 的 auto 规则未命中 `send_from_directory` + 用户可控 filename 的组合

### 误报模式归纳

| 模式 | 数量 | 根因 |
|---|---|---|
| Vendored JS 库（new RegExp/eval/document.write） | ~70 | semgrep 对 JS 文件产生大量匹配，`--no-git-ignore` 扫入了 project_template 下的前端资源 |
| CLI-only 代码（Click 子命令） | 3 | semgrep 不区分 HTTP 入口和 CLI 入口，分诊层已正确清除 |
| Admin-only/启动时配置 | 3 | sink 真实但 source 仅限已认证管理员或应用启动阶段 |
| 第三方服务集成（AdSense SRI） | 1 | 非用户可控的安全配置建议 |
