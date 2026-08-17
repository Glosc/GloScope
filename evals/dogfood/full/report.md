# 寻幽 (GloScope) 漏洞审计报告

- 目标仓库：`C:\Users\--sora--\AppData\Local\Temp\dogfood-quokka`
- 生成时间：2026-08-17T17:44:39+00:00

## 漏斗摘要

| 层 | 结果 |
|---|---|
| 候选（semgrep） | 108 |
| 分诊保留 / 砍掉 | 27 / 81 |
| 确认 confirmed | 2 |
| 误报 false_positive | 23 |
| 存疑 inconclusive | 2（其中执行错误 2） |

- Token 成本：分诊 137602/28732（in/out），验证 20950384/233494（in/out），合计 21350212
- 耗时：semgrep 30.7s · 分诊 388.7s · 验证 4879.2s

## 确认漏洞（confirmed）

### 1. [high] CWE-79 — quokka\core\content\models.py:50

- 规则：`python.django.security.audit.xss.html-magic-method.html-magic-method`
- 代码：`def __html__(self):
        return str(self)`
- 污点链：
  - `quokka/core/content/__init__.py:174 - 公开路由 /<path:category>/ 将 URL 路径原样绑定到 ArticleListView.get(category)`
  - `quokka/core/content/views.py:94 - get() 接收 category 参数，未做任何白名单、HTML 转义或正则转义`
  - `quokka/core/content/views.py:113 - category 被直接拼入 $regex 查询；可构造正则匹配已有 published 文章以绕过空结果 404`
  - `quokka/core/content/views.py:176 - 同一 category 被包装为 Category(category) 并放入模板上下文`
  - `quokka/core/content/models.py:101 - Category.__str__ 返回未经净化的原始 self.category`
  - `quokka/core/content/models.py:50 - Orderable.__html__ 返回 str(self)，使 Jinja/MarkupSafe 将其视为安全 Markup`
  - `quokka/core/content/views.py:200 - render_template 渲染 category.html，无显式 escape 过滤`
  - `quokka/templates/category.html:3 - {{ category }} 直接输出 Orderable 对象`
- PoC 思路：前提是数据库中存在至少一篇已发布文章且其 category_slug 以 blog 开头。请求 /blog(?:%3Cscript%3Ealert(1)%3C/script%3E)*/，category 解码后为 blog(?:<script>alert(1)</script>)*；$regex 因可选分组可匹配 blog，绕过空分类 404，随后 __html__ 导致 <script>alert(1)</script> 原样输出。
- 依据：source 是公开路由的 URL path，完全用户可控且无净化；sink 是 Orderable.__html__ 直接返回 str(self)，其中 Category.__str__ 返回原始 category。Flask/Jinja 对 .html 模板默认 autoescape，但 MarkupSafe 对带 __html__ 的对象会直接采用返回值而不转义，因此 category.html 中 {{ category }} 形成反射型 XSS。空分类 404 可通过正则注入（可选分组）绕过，只要存在 category_slug 前缀为 blog 的已发布文章。
- 分诊理由：__html__返回str(self)可能包含用户输入，绕过Django转义构成潜在XSS，需追污点链验证。
### 2. [medium] CWE-1333 — quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:254

- 规则：`javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- 代码：`pat = new RegExp(d_w[f].substring(1), 'i');`
- 污点链：
  - `quokka/project_template/themes/bootstrap3/templates/base.html:154 - 搜索表单以 GET 将 name=q 提交到 /search.html，q 由外部用户控制`
  - `quokka/project_template/themes/bootstrap3/templates/search.html:16 - 搜索页初始化 #tipue_search_input 的 tipuesearch 插件，加载 tipuesearch.min.js/packed 代码`
  - `quokka/project_template/themes/bootstrap3/static/tipuesearch/tipuesearch.js:100 - getURLP('q') 从 location.search 提取 q，写入输入框并调用 getTipueSearch(0,true)`
  - `quokka/project_template/themes/bootstrap3/static/tipuesearch/tipuesearch.js:129 - d = $('#tipue_search_input').val().toLowerCase()，污点进入搜索词`
  - `quokka/project_template/themes/bootstrap3/static/tipuesearch/tipuesearch.js:139 - d_w = d.split(' ')，仅按空格分词，后续 stop-word/stem 替换未做正则转义或白名单`
  - `quokka/project_template/themes/bootstrap3/static/tipuesearch/tipuesearch.js:254 - pat = new RegExp(d_w[f].substring(1), 'i')，把用户可控词去掉前缀 '-' 后直接作为正则`
  - `quokka/project_template/themes/bootstrap3/static/tipuesearch/tipuesearch.js:255 - 对每个页面的 title/text/tags 执行 pat.search()，恶意嵌套量词可导致指数级回溯/ReDoS`
- PoC 思路：在启用 bootstrap3 主题及 Tipue Search 的站点访问 /search.html?q=-%28%5B%5Cw%5Cs%5D%2B%29%2B%23。脚本加载后自动把 q 写入输入框并搜索；排除词分支中 substring(1) 得到 ([\w\s]+)+#，对页面正文调用 String.search 时因贪婪嵌套量词且末尾字符不匹配产生指数级回溯，页面长时间无响应、CPU 占用。
- 依据：q 参数经 getURLP 解码后进入输入框并自动触发搜索；d_w 仅经过 toLowerCase/trim、按空格分词、停用词过滤和词干替换，均未对正则元字符进行转义或白名单校验。第 254 行在 token 以 '-' 开头时去除 '-' 后直接把剩余字符串传入 new RegExp，并在第 255 行对页面 title/text/tags 执行 search，构成可被恶意链接触发的客户端 ReDoS。可达性依赖 bootstrap3 主题及 Tipue Search 页面被启用，但该主题模板和搜索表单均已提供加载/触发路径。
- 分诊理由：无法确定 d_w 的来源是否受外部输入影响，需进一步追污点链验证。

## 存疑（inconclusive）

- `quokka\admin\actions.py:151` — python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup ⚠️ 验证输出不可解析: Expecting value: line 1 column 1 (char 0)
- `quokka\core\content\formats.py:407` — python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup ⚠️ 验证输出不可解析: Expecting value: line 1 column 1 (char 0)

## 验证为误报（false_positive）

- `quokka\admin\actions.py:90` — python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup（CWE-79）：The Markup() sink is real and would disable auto-escaping, but the interpolated user['username'] is not externally controllable by an unauthenticated attacker. Users are only written by the local CLI command 'quokka adduser' (quokka/cli.py:148) or through the flask-admin UserView create/edit form, which is registered only when ADMIN_REQUIRES_LOGIN is true (quokka/core/auth.py:148-153) and is protected by RequiresLogin (quokka/admin/views.py:16). The action itself is also an admin-only bulk action. There is no public registration/signup route or other HTTP path that writes the users collection, so untrusted input cannot reach this sink.
- `quokka\cli.py:182` — python.lang.security.audit.eval-detected.eval-detected（CWE-94）：sink 确实使用 eval，且 `line` 未做任何净化；但该 `execute` 命令是通过 Click 注册的本地 CLI 子命令，只可由运行 `quokka execute <code>` 的本地用户触发。仓库内没有 Flask/HTTP 路由调用 `quokka.cli:execute` 或 `eval`，提供的 HTTP 入口索引中也不存在对应入口。攻击者若已能本地执行该 CLI，通常已拥有同进程执行任意 Python 的能力，未跨越任何远程安全边界，因此对 Web 远程攻击面不构成可达漏洞。
- `quokka\core\blueprints.py:43` — python.lang.security.audit.non-literal-import.non-literal-import（CWE-706）：候选 sink 确实存在，但没有任何 HTTP 参数、请求体、header 或上传文件名流入 module_name。该函数 load_from_folder 遍历本地 BLUEPRINTS_PATH 目录下的子目录名并动态导入模块；源码全局搜索显示 load_from_folder 仅被定义、未被任何调用方或启动路径引用，因此该 sink 当前不可达。即使函数被调用，其输入也来自部署者控制的应用配置和本地文件系统目录结构，而非远程用户输入，且函数本身要求目录和 main.py 存在。故判定为静态扫描误报。
- `quokka\core\blueprints.py:50` — python.lang.security.audit.non-literal-import.non-literal-import（CWE-706）：sink 确实存在，但数据源不是远程用户可控的 HTTP 参数、请求体、header 或上传文件名。fname 来自服务端本地目录 os.listdir(path)，path 由 app.config 的 BLUEPRINTS_PATH/PROJECT_ROOT 决定。更关键的是 load_from_folder 在整个仓库中只有定义、没有任何调用点，应用创建路径 create_app 只调用 configure_dynaconf 和 configure_extensions，不会执行该函数，因此该分支对 Web 请求不可达。即便函数被执行，也仅加载本地已存在的模块目录，攻击者无法通过 HTTP 请求影响导入名。
- `quokka\core\commands_collector.py:47` — python.lang.security.audit.non-literal-import.non-literal-import（CWE-706）：该 sink 存在，但输入只来自 Click 命令行子命令名，且 `CommandsCollector`/`blueprint_commands` 未注册到任何 HTTP 路由；默认配置 `quokka/project_template/quokka.yml:690` 中 `click_commands: []`，仓库内也没有调用 `blueprint_commands` 的入口。即使本地 CLI 用户传入命令名，导入路径也始终被限制在 `quokka.modules.*.commands.*` 命名空间下，无法指定任意顶层模块。因此不构成可远程触达的任意代码导入漏洞。
- `quokka\core\content\models.py:369` — python.django.security.audit.xss.html-magic-method.html-magic-method（CWE-79）：Sink exists at quokka/core/content/models.py:369 (Content.__html__ returns raw str(self), which derives from DB fields such as title/name/_id). However, no bundled template interpolates a whole Content/Article/Page/Block object, so Jinja never invokes Content.__html__; templates access attributes like article.title, article.summary, page.content, which are autoescaped (only explicitly Markup-wrapped content is raw by design). The only write path for title is the Flask-Admin content form (quokka/core/content/formats.py:165 -> quokka/core/content/admin.py:178), which is gated by RequiresLogin (quokka/admin/views.py:13) with ADMIN_REQUIRES_LOGIN: true by default (quokka/project_template/quokka.yml:433). There is no unauthenticated HTTP source and no reachable sink route for this specific flagged method.
- `quokka\core\content\models.py:468` — python.lang.security.dangerous-globals-use.dangerous-globals-use（CWE-96）：该规则把非静态下标访问 globals() 判为危险，但此处 globals() 返回的是模块全局符号字典，不是用户代码注入点。model_name 由 content_type.lower().split('_') 后逐词 capitalize() 拼接而成，攻击者即使控制 content_type，也只能得到形如 Content、Article、Page、Block、BlockItem、Category、Tag、Author、Url、Fixed、Series、Orderable、Paginator 的名称，无法生成带下划线或小写的关键内置/导入符号（如 __import__、eval、exec、open）。可命中的类构造函数只做字段赋值、slug 化和分页封装，不存在任意代码执行；未命中时回退为 Content(content)。此外管理端创建内容时 content_type 被 base_query 固定，BlockItem 隐藏字段也默认为 block_item。因此候选漏洞不可达且无可利用的代码执行效果，属于误报。
- `quokka\core\flask_dynaconf.py:112` — python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup（CWE-79）：The sink at quokka/core/flask_dynaconf.py:112 runs only during application startup (create_app_base -> configure_dynaconf, see quokka/__init__.py:16). The values iterated come exclusively from app.theme_context, which is populated from hardcoded defaults, theme sections of quokka.yml/.secrets.yml, and QUOKKA_THEME_* environment variables (lines 47-107). No HTTP request data (query params, form body, headers, path segments, or upload filenames) is merged into app.theme_context before this loop, and none of the indexed HTTP routes can influence it at this point. Markup() therefore marks trusted deployment-owned theme configuration as safe rather than attacker-controlled input, so there is no remote XSS trigger from this sink.
- `quokka\project_template\themes\Flex\templates\article.html:33` — html.security.audit.missing-integrity.missing-integrity（CWE-353）：该候选属于缺少 Subresource Integrity 的静态配置问题，而非由用户输入触达的注入漏洞。第 33 行 script 的 src 完全硬编码为 Google AdSense 域名，且被第 32 行 `{% if GOOGLE_ADSENSE and GOOGLE_ADSENSE.ads.article_top %}` 条件包裹；仓库中没有任何 HTTP 参数、请求体、header 或上传内容流入该 src，GOOGLE_ADSENSE 也未被默认配置启用。因此不存在攻击者可控的污点源和可达的 source→sink 链，缺少 integrity 只是浏览器资源完整性加固建议，不能证明远程可利用漏洞。
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:205` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：The source-to-sink flow is present in the Tipue Search client-side library and lacks regex escaping, but the sink is not reachable in the shipped Quokka application. It only executes in a browser on a rendered search page, and no Python route renders bootstrap3/search.html. The default theme is ACTIVE: malt (quokka/project_template/quokka.yml:42), while /theme/<path:filename> serves only the active theme's static directory (quokka/core/themes.py:33-34), so /theme/tipuesearch/tipuesearch.js resolves under themes/malt/static and does not exist. Even with bootstrap3 active and search.html rendered, the default branch loads tipuesearch.min.js rather than tipuesearch.js unless the unconfigured assets plugin is enabled. Therefore the candidate sink cannot be externally triggered in the default deployment.
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:221` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：The taint chain inside the client-side Tipue Search plugin is real: the q URL parameter reaches new RegExp without regex escaping, so a crafted query could create an expensive regex. However, the sink is only executed when a search page loads and calls $().tipuesearch(...). In this Quokka Flask application there is no registered route that renders search.html; the HTTP entry index contains only static serving for /theme/<path:filename> (quokka/core/themes.py:34), which returns JS bytes without evaluating them. The default theme is malt, bootstrap3's tipue_search is not enabled by default, and search.html is only a Pelican direct template, not a registered Quokka route. Therefore the vulnerable branch is not externally reachable in the audited application.
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:225` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：sink 确实由 q 派生出的 d_w[f] 动态构造正则且未做元字符转义，存在理论上的客户端 ReDoS 模式。但该文件是第三方浏览器端静态资源，唯一的 HTTP 入口是 Flask 静态路由 /theme/<path:filename>，服务端仅返回文件字节，不解析 q 也不执行 RegExp，攻击者无法通过该请求触达 sink。默认主题 ACTIVE=malt，未启用 bootstrap3；即使启用 bootstrap3，search.html 也没有对应的 Quokka 路由，执行只发生在访问者浏览器中，不能造成服务端主线程阻塞。因此该 semgrep 命中属于客户端第三方静态脚本误报，不构成可远程利用的应用漏洞。
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:281` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：数据流在浏览器内确实存在，但该 sink 位于 vendored 的客户端搜索插件中，q 参数不会发送到 Flask 后端参与正则编译。唯一相关的后端入口 quokka/core/themes.py:34 仅通过 send_from_directory 返回静态 JS 文件，不在服务端执行该正则。搜索页面只在 bootstrap3 主题且启用 tipue_search/search 插件时生成；当前默认配置 quokka/project_template/quokka.yml:42 使用 ACTIVE: malt，未注册 /search.html 路由，也没有服务端 ReDoS 面。因此 semgrep 的 non-literal RegExp 提示属于客户端静态脚本的代码质量/自损型问题，不是可远程利用的服务端漏洞。
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:297` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：The sink exists, but it is not reachable in the application's actual configuration. Line 297 is inside `if (set.highlightEveryTerm)`, and the plugin defaults `highlightEveryTerm` to false at quokka/project_template/themes/bootstrap3/static/tipuesearch/tipuesearch.js:23. The only in-repo initialization, quokka/project_template/themes/bootstrap3/templates/search.html:16-20, does not override that option. No other code in the repository sets `highlightEveryTerm` to true, so this branch is dead. Additionally, the JavaScript file is served as a static theme asset; no server-side route executes this regex.
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:301` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：代码层面存在动态正则拼接且无转义，但该脚本是 bootstrap3 主题的可选 Tipue Search 静态资源。当前项目默认主题为 malt（quokka/project_template/quokka.yml:42），/theme/<path> 只服务活动主题静态目录，因此该 bootstrap3 文件默认不会被提供。更关键的是，仓库中没有注册任何渲染 search.html 或加载 tipuesearch.js 的 Flask 路由；/search.html 会命中内容详情路由 /<path:slug>.<ext>（quokka/core/content/__init__.py:191），在无对应 content 时返回 404，且 Tipue Search 所需的 tipuesearch_content.json 也不存在。因此该 sink 在当前应用中无法被外部请求触达，属于不可达误报。
- `quokka\project_template\themes\clean\static\js\clean-blog.js:955` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：The sink exists, but the regex pattern is not remotely attacker-controlled. `regexFromString` is only called by the regex validator, which reads the pattern from an HTML `data-validation-*-regex` attribute on an input element. The clean theme templates contain no rendered input/form elements carrying such attributes, and no route reflects request parameters, headers, or upload names into that DOM attribute. The only way to inject an arbitrary pattern would be authenticated admin-authored HTML/Markdown content, which is behind `ADMIN_REQUIRES_LOGIN`; that is not the unauthenticated ReDoS source required for this finding. The static JS route `/theme/<path:filename>` serves the file without influencing `inputstring`.
- `quokka\project_template\themes\octopress\static\js\ender.js:22` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：该 sink 确实存在于静态第三方前端库 ender.js 的 reqwest 模块中，但 source 是 reqwest 选项 a.jsonpCallback，默认值为硬编码的 "callback"，不是 HTTP 参数、请求体、header 或上传文件名。搜索 quokka 仓库未发现 octopress 主题或应用代码调用 reqwest/ajax/jsonp/jsonpCallback 并传入用户可控值；该文件仅由 base.html 作为 <script src="/theme/js/ender.js"> 引入，通过 quokka/core/themes.py:34 的 theme_static 以静态文件返回，服务端不执行其中的 JS。因此不存在从外部 HTTP 请求到该动态 RegExp 的远程可达污点链，也无法造成服务端 ReDoS。
- `quokka\project_template\themes\octopress\static\js\ender.js:22` — javascript.browser.security.eval-detected.eval-detected（CWE-94）：该告警命中 quokka/project_template/themes/octopress/static/js/ender.js:22，属于打包的第三方 Ender/Reqwest 客户端库。此处的 eval 有两个分支：1) 仅当浏览器无 window.JSON 时用 eval('('+r+')') 解析 JSON；2) 当请求 type 为 'js' 时 eval(r)，其中 r 是 XHR 的 responseText。源不是服务端 HTTP 请求参数/请求体/header，而是浏览器端 Ajax 响应，无法由外部请求直接控制。该主题中唯一的 Reqwest 调用在 static/js/github.js:15，显式使用 type:'jsonp'，走 script 注入分支而非 XHR success/eval 分支，且其 URL 来自服务端配置 GITHUB_USER，不来自用户输入。静态路由 /theme/<path:filename> 仅把 JS 文件字节返回给浏览器，不会在服务端执行 eval。未发现从用户可控输入到该 eval 的可达调用链，属于 semgrep 对第三方压缩库的通用误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:38` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：The sink exists (new RegExp built from parameter a in the vendored Bonzo/ender.js), but no attacker-controlled value reaches it. The file is served as a static client-side asset; the Flask route only returns file bytes and does not execute JavaScript. The application code that uses this library (octopress.js) calls addClass/hasClass/removeClass/toggleClass with hardcoded strings. No HTTP parameter, request body, header, URL fragment, or other user-controlled source is passed into those class-name helpers. Even a crafted browser-side call would only cause client-side slowdown in the attacker's own browser, not a server-side ReDoS. Therefore the candidate is a library-level static pattern, not a remotely reachable vulnerability.
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：候选 sink 位于第三方客户端库 qwery/ender 的静态 JS 中，quokka/core/themes.py:34 的 /theme/<path:filename> 仅通过 send_from_directory 返回静态文件，服务端不会执行该 JS。quokka/project_template/themes/octopress/templates/base.html:80 只是以静态脚本加载，页面内 octopress.js 对 qwery/$(...) 的调用均为硬编码选择器，未发现 HTTP 参数/请求体/header/上传文件名等污点流入该库。即便考虑客户端选择器输入，quokka/project_template/themes/octopress/static/js/ender.js:45 中动态 RegExp 的来源要么经 V()（E=/([.*+?\^=!:${}()|\[\]\/\\])/g）转义，要么被 w=/\.[\w\-]+/g 或 A=/^([\w]+)?\.([\w\-]+)$/ 限制为 [\w-]+，不能构成可控的灾难性回溯。因此不满足远程可达且无净化的条件。
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：候选 sink 位于前端静态资源 quokka/project_template/themes/octopress/static/js/ender.js:45，是 vendored Ender/qwery DOM 选择器库中的 new RegExp(V(c))。该文件仅由 Flask 路由 /theme/<path:filename> 通过 send_from_directory 以静态字节流返回（quokka/core/themes.py:34），服务端 Python 不执行此 JavaScript，因此攻击者无法通过 HTTP 参数在服务端触发 RegExp 导致 CPU 阻塞。sink 中的 c 来自浏览器端 CSS 属性选择器解析，而非服务端 HTTP 请求参数；主题内对 $() 的调用均为硬编码选择器（如 quokka/project_template/themes/octopress/static/js/octopress.js），未发现将用户可控数据传入该选择器引擎的路径。综上，该检测缺少从外部请求到服务端正则执行的污点链，属于静态资源误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：该文件是 vendored 的 qwery/ender 客户端静态资源。动态 RegExp 位于 qwery 的 CSS 选择器匹配逻辑中，且属性值匹配路径 V(c) 会对正则元字符做转义；更关键的是，仓库中没有任何用户可控数据到达 qwery/$：octopress.js 的所有选择器都是硬编码字符串，/theme/<filename> 路由也只是用 send_from_directory 返回 JS 文件内容，不会在服务端执行。因此不存在可远程触达的 ReDoS 污染链，属于静态规则对客户端库非字面量 RegExp 的误报。
- `quokka\project_template\themes\octopress\static\js\twitter.js:10` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp（CWE-1333）：该 sink 的动态正则模式来自内部辅助函数 p(e,c) 的 c 参数，但调用点全部使用硬编码的 CSS 类名字符串（tweet、e-entry-title、p-author、dt-updated、retweet-credit），未发现任何 HTTP 参数、请求体、header、上传文件名或配置内容流入 c。因此不存在攻击者可控的正则表达式，也无法构成 ReDoS 的污点链。该文件仅作为静态 JS 通过 /theme/<path:filename> 提供，属于前端脚本；即使被请求，正则模式仍固定。

## 分诊砍掉（dropped at triage）

- `quokka\core\content\views.py:269` — python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1：SHA1仅用于生成guid，非安全签名或密码哈希，不构成实际风险
- `quokka\project_template\themes\Flex\templates\article.html:80` — html.security.audit.missing-integrity.missing-integrity：外部脚本为固定URL，无用户可控输入，缺失integrity不构成可利用污点链。
- `quokka\project_template\themes\Flex\templates\base.html:14` — html.security.audit.missing-integrity.missing-integrity：候选为静态模板中CDN资源缺少integrity属性，无外部输入数据流到危险sink，属配置类问题而非污点链。
- `quokka\project_template\themes\Flex\templates\base.html:70` — html.security.audit.missing-integrity.missing-integrity：该候选是外部静态脚本缺少SRI完整性属性，属于配置/最佳实践问题，无外部输入流向危险sink的污点链，明显误报。
- `quokka\project_template\themes\Flex\templates\base.html:121` — html.security.audit.missing-integrity.missing-integrity：该候选是固定外部脚本URL，无外部输入流入危险sink，不属于污点链模式，应视为误报。
- `quokka\project_template\themes\Flex\templates\base.html:133` — html.security.audit.missing-integrity.missing-integrity：静态模板中硬编码的外部脚本标签，无外部输入流向此 sink，属于完整性最佳实践，非污点链误报。
- `quokka\project_template\themes\Flex\templates\base.html:181` — html.security.audit.missing-integrity.missing-integrity：该候选是 SRI 缺失问题，不涉及外部输入到危险 sink 的污点链，属配置类告警，无需深度污点分析。
- `quokka\project_template\themes\Flex\templates\index.html:6` — html.security.audit.missing-integrity.missing-integrity：外部脚本地址为静态字符串，无外部输入流入危险 sink，属于完整性属性缺失的最佳实践提示，非污点链。
- `quokka\project_template\themes\Flex\templates\index.html:57` — html.security.audit.missing-integrity.missing-integrity：仅为外部脚本缺少 integrity 属性，无外部输入流向危险 sink，属最佳实践类问题。
- `quokka\project_template\themes\Flex\templates\partial\cc_license.html:2` — html.security.plaintext-http-link.plaintext-http-link：模板中硬编码的HTTP链接，非外部输入且非危险sink，属于明显误报。
- `quokka\project_template\themes\Flex\templates\partial\cc_license.html:6` — html.security.plaintext-http-link.plaintext-http-link：模板中硬编码的 HTTP 链接指向固定域名，外部变量仅影响路径，不构成用户输入导向危险 sink 的污点链。
- `quokka\project_template\themes\Flex\templates\partial\flex.html:2` — html.security.plaintext-http-link.plaintext-http-link：该http链接为模板中的静态常量，并非外部输入导向的危险操作，属于明显误报。
- `quokka\project_template\themes\Flex\templates\partial\flex.html:4` — html.security.plaintext-http-link.plaintext-http-link：这是模板中硬编码的静态HTTP链接，无外部输入参与，不构成污点链，属于明显误报。
- `quokka\project_template\themes\Flex\templates\partial\statuscake.html:10` — html.security.audit.missing-integrity.missing-integrity：外部固定URL脚本缺少integrity属性属于安全加固建议，无外部输入污染的污点链，明显误报。
- `quokka\project_template\themes\bootstrap3\static\tipuesearch\tipuesearch.js:98` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：name 为内部函数参数，实际调用时由硬编码字符串传入，非外部输入，且正则模式简单不构成 ReDoS
- `quokka\project_template\themes\bootstrap3\templates\article.html:106` — html.security.audit.missing-integrity.missing-integrity：该候选是缺失 SRI 属性，属于安全加固问题，不涉及外部输入到危险 sink 的污点链，不适合深度污点验证。
- `quokka\project_template\themes\bootstrap3\templates\includes\comments.html:36` — html.security.plaintext-http-link.plaintext-http-link：链接为静态常量，不涉及外部输入流向危险 sink，明显误报。
- `quokka\project_template\themes\bootstrap3\templates\includes\comments.html:38` — html.security.plaintext-http-link.plaintext-http-link：候选为模板中硬编码的静态链接，无外部输入流向危险sink，属于明显误报。
- `quokka\project_template\themes\bootstrap3\templates\includes\footer.html:16` — html.security.plaintext-http-link.plaintext-http-link：链接是硬编码的静态HTTP地址，无外部输入参与，不构成污点链。
- `quokka\project_template\themes\bootstrap3\templates\includes\footer.html:17` — html.security.plaintext-http-link.plaintext-http-link：静态常量链接，无外部输入，非危险 sink，明显误报
- `quokka\project_template\themes\bootstrap3\templates\includes\liquid_tags_nb_header.html:146` — html.security.audit.missing-integrity.missing-integrity：该候选是静态模板中缺失SRI属性的最佳实践问题，无外部输入流向危险sink，明显非污点链。
- `quokka\project_template\themes\bootstrap3\templates\includes\sidebar\twitter_timeline.html:8` — html.security.audit.missing-integrity.missing-integrity：该候选为缺少SRI完整性属性，不涉及外部输入流向危险sink，属于明显误报。
- `quokka\project_template\themes\clean\static\js\clean-blog.js:969` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：该行仅为属性读取，未将外部输入写入对象原型，且无直接污点链证据，属于疑似误报。
- `quokka\project_template\themes\clean\static\js\jquery.js:1673` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：候选为jQuery库中常规DOM遍历循环，不构成外部输入导向危险sink的原型污染模式，明显误报。
- `quokka\project_template\themes\clean\static\js\jquery.js:2074` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：第三方库jQuery的正常DOM遍历代码，非外部输入导向原型污染，明显误报。
- `quokka\project_template\themes\clean\static\js\jquery.js:2088` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：第三方jQuery库中DOM遍历循环，非外部输入导向原型污染，明显误报。
- `quokka\project_template\themes\clean\static\js\jquery.js:2096` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：第三方库 jquery.js 中的常规 DOM 遍历循环，非外部输入导向原型污染 sink，属明显误报
- `quokka\project_template\themes\clean\static\js\jquery.js:2828` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：该代码为jQuery库内部DOM遍历循环，无外部输入导向危险sink，属于明显误报。
- `quokka\project_template\themes\clean\static\js\jquery.js:2933` — javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop：第三方jQuery库通用代码，无外部输入流向原型污染sink，属明显误报
- `quokka\project_template\themes\clean\templates\base.html:63` — html.security.audit.missing-integrity.missing-integrity：外部CDN静态链接缺失integrity属性，不涉及外部输入流向危险sink的污点链，属于配置问题而非可利用模式。
- `quokka\project_template\themes\clean\templates\base.html:70` — html.security.audit.missing-integrity.missing-integrity：该候选仅为外部静态脚本缺少SRI完整性，属于最佳实践问题，并非外部输入流向危险sink的污点链。
- `quokka\project_template\themes\clean\templates\base.html:71` — html.security.audit.missing-integrity.missing-integrity：该候选是静态资源缺少SRI完整性属性，不涉及将外部输入导向危险sink，属于配置类问题而非污点链误报。
- `quokka\project_template\themes\clean\templates\footer.html:2` — html.security.plaintext-http-link.plaintext-http-link：模板中静态硬编码的HTTP链接，无外部输入参与，不构成敏感数据明文传输风险。
- `quokka\project_template\themes\clean\templates\footer.html:3` — html.security.plaintext-http-link.plaintext-http-link：静态模板中的固定HTTP链接，无外部输入与危险sink，属明显误报。
- `quokka\project_template\themes\clean\templates\sharing.html:19` — html.security.audit.missing-integrity.missing-integrity：该候选是缺失SRI完整性属性的配置问题，不涉及外部输入导向危险sink的污点链模式。
- `quokka\project_template\themes\hyde\templates\base.html:4` — html.security.audit.missing-integrity.missing-integrity：该链接是模板中固定的外部资源引用，不涉及外部输入，且缺少integrity属性属于最佳实践问题而非污点链。
- `quokka\project_template\themes\hyde\templates\base.html:30` — html.security.audit.missing-integrity.missing-integrity：候选是模板中静态CDN链接缺少integrity属性，不涉及外部输入流向危险sink，非污点链误报。
- `quokka\project_template\themes\malt\static\js\materialize.js:221` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：候选位于第三方压缩库内部，RegExp 的参数来自内部常量或变量，并非外部输入导向危险 sink，属于明显误报。
- `quokka\project_template\themes\malt\static\js\materialize.js:221` — javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring：第三方库压缩代码中的调试日志，非应用外部输入直达sink，明显误报。
- `quokka\project_template\themes\malt\static\js\materialize.js:221` — javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring：第三方压缩库代码，无可信外部输入流入危险sink，疑似误报。
- `quokka\project_template\themes\malt\static\js\materialize.js:221` — javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring：该候选位于第三方压缩库内，拼接的是库内部变量，非外部输入，且不属于可利用的格式串漏洞，属明显误报。
- `quokka\project_template\themes\malt\templates\includes\comments.html:38` — html.security.plaintext-http-link.plaintext-http-link：纯静态模板中的固定 http 链接，不涉及外部输入流向危险 sink，属于明显误报。
- `quokka\project_template\themes\malt\templates\includes\comments.html:39` — html.security.plaintext-http-link.plaintext-http-link：这是一个硬编码的静态HTTP链接，并非外部输入导向危险sink，属于明显误报。
- `quokka\project_template\themes\malt\templates\includes\footer.html:41` — html.security.plaintext-http-link.plaintext-http-link：静态模板中的固定HTTP链接，无外部输入参与，属明显误报。
- `quokka\project_template\themes\malt\templates\membros.html:28` — html.security.plaintext-http-link.plaintext-http-link：模板中链接固定使用http协议，外部输入仅拼入路径而非协议，不构成可被外部控制的明文传输危险点，属于代码质量问题而非污点链。
- `quokka\project_template\themes\malt\templates\membros.html:31` — html.security.plaintext-http-link.plaintext-http-link：模板中硬编码 HTTP 前缀，外部输入仅拼接为用户名，无命令或注入风险，属明显误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:32` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：构造RegExp所用的事件名来自库内部调用，并非外部输入直接流向危险sink，属明显误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:32` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：该正则由内部事件名字符串构造并用于匹配内部键，并非外部用户输入直接控制，属于第三方库常见误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：正则参数来自CSS类名匹配（仅含\w和连字符）且经过转义，无外部可控危险输入，属明显误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：该RegExp由选择器解析出的子串经V()转义后构造，未发现外部输入直通此库的污点链，属明显误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：该 RegExp 由库内部选择器解析逻辑构造，参数并非外部可控输入，属于第三方库代码的误报。
- `quokka\project_template\themes\octopress\static\js\ender.js:45` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：该代码是第三方库内部的选择器解析逻辑，正则表达式由开发人员提供的选择器字符串构造，并非外部用户输入直接控制，属于明显误报。
- `quokka\project_template\themes\octopress\static\js\modernizr-2.0.js:5` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：代码位于第三方库静态文件中，正则由硬编码字符串拼接生成，无外部输入流入，属于明显误报。
- `quokka\project_template\themes\octopress\static\js\modernizr-2.0.js:5` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：第三方库Modernizr内部常量拼接正则，无外部输入流向危险sink，属明显误报。
- `quokka\project_template\themes\octopress\static\js\modernizr-2.0.js:5` — javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp：该正则的拼接参数来自库内部硬编码字符串，并非外部输入，属于第三方库误报。
- `quokka\project_template\themes\octopress\templates\_includes\disqus_thread.html:1` — html.security.plaintext-http-link.plaintext-http-link：静态模板中的固定链接，无外部输入流向危险 sink，属明显误报。
- `quokka\project_template\themes\octopress\templates\_includes\footer.html:10` — html.security.plaintext-http-link.plaintext-http-link：该链接是模板中的静态硬编码常量，不涉及外部输入流向危险sink，属明显误报。
- `quokka\project_template\themes\octopress\templates\_includes\navigation.html:4` — html.security.plaintext-http-link.plaintext-http-link：模板中静态HTTP链接，非外部输入直达危险sink，属于低危最佳实践提示
- `quokka\project_template\themes\octopress\templates\_includes\sharing.html:3` — html.security.plaintext-http-link.plaintext-http-link：硬编码的http链接，无外部输入流向sink，属于明显的常量误报
- `quokka\project_template\themes\octopress\templates\_includes\twitter_sidebar.html:41` — html.security.plaintext-http-link.plaintext-http-link：模板中拼接的是配置变量而非外部输入，且仅为HTTP链接提示，不属于污点链模式。
- `quokka\project_template\themes\octopress\templates\_includes\twitter_sidebar.html:43` — html.security.plaintext-http-link.plaintext-http-link：这是模板中静态HTTP链接，不涉及外部输入导向危险sink，属于最佳实践提示而非漏洞。
- `quokka\project_template\themes\octopress\templates\base.html:18` — html.security.audit.missing-integrity.missing-integrity：该候选是模板外部资源缺少integrity属性的配置检查，无外部输入流向危险sink，不构成污点链。
- `quokka\project_template\themes\pure\templates\article.html:9` — html.security.audit.missing-integrity.missing-integrity：这是模板中静态CDN脚本缺失integrity属性，属于配置缺失而非外部输入流向危险sink的污点链。
- `quokka\project_template\themes\pure\templates\base.html:29` — html.security.audit.missing-integrity.missing-integrity：静态模板中固定CDN链接，非外部输入导向危险sink，属于最佳实践缺失而非污点链误报
- `quokka\project_template\themes\pure\templates\base.html:30` — html.security.audit.missing-integrity.missing-integrity：静态CDN链接无外部输入流入，缺少SRI不是可追污点链的漏洞模式
- `quokka\project_template\themes\pure\templates\base.html:34` — html.security.audit.missing-integrity.missing-integrity：这是CDN资源缺少integrity属性的最佳实践问题，不涉及外部输入流向危险sink的污点链
- `quokka\project_template\themes\pure\templates\disqus.html:14` — html.security.plaintext-http-link.plaintext-http-link：链接为静态常量，无外部输入且不涉及污点链，属明显误报。
- `quokka\project_template\themes\pure\templates\disqus.html:15` — html.security.plaintext-http-link.plaintext-http-link：硬编码静态链接，无外部输入，非污点链，属明显误报
- `quokka\project_template\themes\pure\templates\footer.html:4` — html.security.plaintext-http-link.plaintext-http-link：硬编码的静态HTTP链接，无外部输入且非危险sink，属于明显误报。
- `quokka\templates\admin\index.html:80` — html.security.plaintext-http-link.plaintext-http-link：硬编码HTTP链接，非外部输入，不构成污点链
- `quokka\templates\admin\quokka\edit.html:29` — html.security.audit.missing-integrity.missing-integrity：这是静态资源缺少SRI完整性校验，不涉及外部输入到危险sink的污点流，属于配置类误报。
- `quokka\templates\admin\quokka\edit.html:30` — html.security.audit.missing-integrity.missing-integrity：该候选只是外部脚本缺少SRI属性，无用户输入流向危险sink，不构成污点链。
- `quokka\templates\base.html:58` — html.security.plaintext-http-link.plaintext-http-link：这是模板中硬编码的静态HTTP链接，无外部输入参与，不构成污点链，属于最佳实践建议而非安全缺陷。
- `quokka\templates\base.html:59` — html.security.plaintext-http-link.plaintext-http-link：候选是模板中硬编码的HTTP链接，无外部输入流向危险sink，明显误报
- `quokka\templates\base.html:60` — html.security.plaintext-http-link.plaintext-http-link：模板中静态写死的HTTP链接，无外部输入流入，属明显误报。
- `quokka\templates\overload_bootstrap3\templates\includes\comments.html:36` — html.security.plaintext-http-link.plaintext-http-link：硬编码HTTP链接，无外部输入流向危险sink，属于常量拼接，明显误报
- `quokka\templates\overload_bootstrap3\templates\includes\comments.html:38` — html.security.plaintext-http-link.plaintext-http-link：候选是硬编码常量http链接，并非外部输入导向危险sink，属于明显误报。
- `quokka\templates\overload_nest\templates\disqus_script.html:36` — html.security.plaintext-http-link.plaintext-http-link：硬编码静态HTML模板中的HTTP链接，无外部输入流向危险sink，属于明显误报。
- `quokka\templates\overload_nest\templates\disqus_script.html:38` — html.security.plaintext-http-link.plaintext-http-link：硬编码的HTTP链接，无外部输入，不是污点链模式
- `quokka\templates\overload_octopress\templates\_includes\disqus_script.html:36` — html.security.plaintext-http-link.plaintext-http-link：该候选仅为模板中静态HTTP链接，无外部输入流向危险sink，属于明显误报。
- `quokka\templates\overload_octopress\templates\_includes\disqus_script.html:38` — html.security.plaintext-http-link.plaintext-http-link：硬编码HTTP链接，无外部输入和危险sink，属于明显误报。

## 未验证（跳过验证层）

（无）
