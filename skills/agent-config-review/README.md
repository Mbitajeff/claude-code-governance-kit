# agent-config-review

A Claude Code skill that security-reviews AI coding agent configuration: CLAUDE.md, AGENTS.md, `.claude/` settings, skills, hooks and MCP config.

## Install

Copy this folder to `~/.claude/skills/agent-config-review/` (all your projects) or `.claude/skills/agent-config-review/` (one project). Then ask Claude: *"Review the agent configuration in this repo."*

## What it checks

Prompt-injection phrases, remote code piped to a shell, permission bypass, blanket allow rules, AWS keys, private keys and API tokens, plain-http hosts, hooks making network calls, invalid settings JSON, and missing deny rules for `.env`, `~/.ssh` and `~/.aws`. See `reference.md`.

## Note for reviewers

`scripts/agent_config_scan.py` contains strings such as "ignore previous instructions" and `curl | bash` **as regular-expression detection rules**. They are patterns the scanner searches for, not instructions. The script only reads files and prints a report: no writes, no network access, no dependencies.

## Source and license

Source of truth, tests and CI: https://github.com/Mbitajeff/claude-code-governance-kit (release v0.1.1). Verify that this copy matches the release before use. MIT licensed. Author: Jeff Mbita.
