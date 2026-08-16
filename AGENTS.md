# 寻幽 (GloScope)

大模型驱动的漏斗式漏洞审计工具：semgrep 候选生成 → LLM 分诊 → codex exec 深度验证 → 报告。
详见 `README.md` 与 `.scratch/gloscope-v1/spec.md`。

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical triage roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: root `CONTEXT.md` + `docs/adr/` (created lazily). See `docs/agents/domain.md`.
