# Changelog

## v0.1.1 (2026-11-25)

- Added copyright and SPDX licence headers to all source files
- Added `SECURITY.md` with private vulnerability reporting
- Added `CHECKSUMS.txt` so copies outside GitHub (for example skill marketplaces) can be verified
- Added `.gitattributes` to keep LF line endings, so checksums match on Windows too
- Skill: the scanner path now works for personal (`~/.claude/skills`) and project installs; added a skill README with a note for reviewers
- CI: moved to actions/checkout@v5, setup-python@v6 and upload-artifact@v5 (Node 24)
- No changes to scanner rules or hook behaviour

## v0.1.0 (2026-11-24)

- First release: `agent-config-scan` with 10 rules and baseline deny checks (text, JSON, SARIF output) and a GitHub Action
- PreToolUse hook that blocks access to secrets; PostToolUse audit-log hook
- Managed-settings deny baseline, MCP allow/deny policy example
- Terraform: monthly and daily Amazon Bedrock budgets, least-privilege agent IAM role
- `agent-config-review` Claude Code skill
