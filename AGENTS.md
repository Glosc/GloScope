# 寻幽 (GloScope)

AI 驱动的对话式代码漏洞审计桌面应用，基于 codex（Rust）分叉 + Tauri 2.0 构建。
之前完全跑通的固定批处理 Python 实现已归档到 `legacy-python/`，仅作行为规范参照。
详见 `README.md` 与 `.scratch/gloscope-v3/spec.md`（当前架构）、
`.scratch/gloscope-v1/spec.md`、`.scratch/gloscope-v2/spec.md`（历史决策记录）。

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical triage roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: root `CONTEXT.md` + `docs/adr/` (created lazily). See `docs/agents/domain.md`.
