# GloScope 的 codex 硬分叉说明

## 导入来源

- 上游仓库：https://github.com/openai/codex
- 导入的子目录：仅上游 monorepo 里的 `codex-rs/`（Rust workspace 部分；上游的
  `codex-cli/`、`sdk/`、`docs/`、`third_party/` 等未导入，GloScope 不需要）
- 导入的版本：tag `rust-v0.147.0`，commit `be6e8eac029b183056b7e4402879f15d2c85f61b`
  （提交日期 2026-08-06）
- 导入日期：2026-08-18
- 导入方式：`git subtree`，squash 成一个提交（commit `8a9e58f517e...`
  "Squashed 'codex-rs/' content from commit 2cb62d61de"），不保留上游逐笔提交历史

## 版本选择理由

上游是 CI bot 驱动的高频 alpha 发布（导入时 `rust-v0.148.0` 已发到
`-alpha.21`，几乎每天多次打 tag）。为避免分叉在一个尚未经过时间检验的
版本上，选择了上一个正式版 `rust-v0.147.0`（而非最新 alpha），在导入时已有
约 12 天的存活期。

## 政策：硬分叉，不追踪上游

- 本仓库自本次导入起**不会**跟踪、合并或 rebase 上游后续变更。
- 后续 codex 上游的更新（新功能、bug 修复、安全补丁）**不会自动同步**。
- 如确有必要引入上游某个具体修复，采用手动 cherry-pick 单个 commit 的方式，
  而不是重新执行 `git subtree pull`。
- 原因：GloScope 需要深度修改 codex 内部（新增 `ToolContributor`、
  自定义工具、审计分支逻辑等），持续追踪上游存在合并冲突成本高、
  且上游发布节奏过快，与 GloScope 自身开发节奏不匹配。

## M1 验证：Windows 原样 build

`cargo build --workspace` 在 Windows 上会在 `v8 v150.4.0` 的 build script 失败：
其下载 `rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.lib.gz` 预编译包时
从 GitHub Releases 收到 404（已用 GitHub API 直接确认：`rusty_v8` 在
`v150.4.0` 这个 tag 下只发布了 `rusty_v8_release_*`/`rusty_v8_simdutf_release_*`
两种变体，没有 `_ptrcomp_` 变体，与 Windows 无关，是上游 `v8`/`rusty_v8` crate
本身的打包缺口）。

依赖 `v8` 的只有三个 crate：`codex-v8-poc`（独立 PoC，无人依赖）、
`codex-code-mode-runtime`/`codex-code-mode-host`（沙箱化 JS "code mode"
工具执行功能，GloScope 不需要这个功能）。排除这三个 crate 后：

```
cargo build --workspace --exclude codex-code-mode-host \
  --exclude codex-code-mode-runtime --exclude codex-v8-poc
```

在 Windows 上干净通过（`Finished dev profile ... in 4m 07s`，exit 0）。
M1 验证标准（"Windows 上原样 build 通过"）以此为准——`ext/gloscope-tools`
不会依赖 `code-mode-*`/`v8-poc`，故这个排除对后续里程碑无影响。

## 后续工作

- `codex-rs/ext/gloscope-tools/`：新增的 GloScope 工具 crate（`run_semgrep`、
  `submit_verdict`、`triage`），参照同级 `codex-rs/ext/web-search/` 的
  `ToolContributor` 实现模式。
- 详见仓库根目录 `.scratch/gloscope-v3/spec.md` 与 `README.md`。
