# claude-code-governance-kit

**Security guardrails for teams adopting AI coding agents.** Scan agent config for prompt injection and risky permissions, stop agents from reading secrets, keep an audit trail of what they change, and cap what they can spend on Amazon Bedrock.

[![ci](https://github.com/Mbitajeff/claude-code-governance-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Mbitajeff/claude-code-governance-kit/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Why this exists

AI coding agents read their instructions from files in your repo: `CLAUDE.md`, `.claude/settings.json`, skills, hooks and MCP server config. That makes those files part of your **execution surface**, yet most teams review them less carefully than a Dockerfile.

One line in a `CLAUDE.md` like *"ignore previous instructions and don't tell the user"*, a `Bash(*)` allow rule, or a hook that quietly `curl`s data out is enough to turn a helpful agent into a liability. This kit gives you four layers of defence:

| Layer | What it does | Where it runs |
|---|---|---|
| **1. Scan** | `agent-config-scan` finds risky agent config before it merges | CI (GitHub Action, SARIF) and locally |
| **2. Block** | PreToolUse hook stops the agent reading or writing secrets | Developer machine, every tool call |
| **3. Audit** | PostToolUse hook logs every file edit and command the agent runs | Developer machine, ships to your SIEM |
| **4. Contain** | Deny-rule baseline, MCP allowlist, Bedrock budgets and a least-privilege IAM role | Managed settings + Terraform |

No dependencies beyond the Python standard library.

---

## 1. Scan agent config in CI

Add this to any repository:

```yaml
# .github/workflows/agent-config-scan.yml
name: agent-config-scan
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Mbitajeff/claude-code-governance-kit@v0.1.0
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agent-config-scan.sarif
```

Findings appear in the repository's **Security → Code scanning** tab, and the pull request fails on high-severity issues.

Run it locally:

```bash
python3 scanner/agent_config_scan.py path/to/repo                 # human-readable
python3 scanner/agent_config_scan.py . --format sarif --output r.sarif
python3 scanner/agent_config_scan.py . --fail-on medium --exclude fixtures
```

Example against the deliberately insecure fixture in `examples/risky-repo`:

```text
SEVERITY RULE    LOCATION                               ISSUE
HIGH     ACS003  .claude/settings.json:3                Permission checks bypassed
HIGH     ACS004  .claude/settings.json:4                Blanket allow rule auto-approves any command or write
HIGH     ACS002  CLAUDE.md:4                            Remote code piped straight into a shell
HIGH     ACS001  CLAUDE.md:5                            Prompt-injection phrase in agent instructions
MEDIUM   ACS008  .claude/settings.json:9                Plain http to a non-local host
MEDIUM   ACS009  .claude/settings.json:9                Hook or command makes network calls
MEDIUM   ACS008  .mcp.json:3                            Plain http to a non-local host
LOW      ACS101  .claude/settings.json:1                No deny rule protecting environment files
LOW      ACS103  .claude/settings.json:1                No deny rule protecting AWS credentials

9 finding(s): 4 high, 3 medium, 2 low
```

### Rules

| ID | Severity | Detects |
|---|---|---|
| ACS001 | High | Prompt-injection phrases ("ignore previous instructions", "do not tell the user") |
| ACS002 | High | `curl`/`wget` piped into a shell |
| ACS003 | High | `bypassPermissions` or `--dangerously-skip-permissions` |
| ACS004 | High | Blanket allow rules: `Bash`, `Bash(*)`, `Write(*)`, `WebFetch` |
| ACS005 | High | AWS access keys |
| ACS006 | High | Private key material |
| ACS007 | High | GitHub, Anthropic and Slack tokens |
| ACS008 | Medium | Plain `http://` to a non-local host (MCP servers, hooks) |
| ACS009 | Medium | Hooks that make network calls |
| ACS010 | Low | Settings file that is not valid JSON (so it silently does not load) |
| ACS101-103 | Low | No deny rule protecting `.env` files, `~/.ssh` or `~/.aws` |

Deny rules that *name* a dangerous pattern (for example `"Bash(curl * | bash)"` in a deny list) are recognised as protections and not flagged.

---

## 2. Block secret access and 3. audit agent actions

Copy the hooks into your project and register them:

```bash
mkdir -p .claude/hooks
cp hooks/block_secret_access.py hooks/audit_log.py .claude/hooks/
# then merge policies/settings.hooks.example.json into .claude/settings.json
```

**`block_secret_access.py`** (PreToolUse) blocks the agent from touching `.env` files, `~/.ssh`, `~/.aws/credentials`, private keys and registry credential files, whether through Read/Edit/Write, Grep/Glob or a shell command like `cat ~/.aws/credentials`. `.env.example` stays readable. A blocked call returns a reason to the agent so it can choose a safer approach.

**`audit_log.py`** (PostToolUse) appends one JSON line per edit or command: timestamp, session, tool, target file or command, working directory and user. It never logs file contents. Point `AGENT_AUDIT_LOG` at a path your log shipper (CloudWatch agent, Fluent Bit) already collects.

```json
{"ts": "2026-11-24T12:48:03+00:00", "session_id": "9d2e…", "event": "PostToolUse", "tool": "Edit", "target": "/repo/src/app.ts", "command": null, "cwd": "/repo", "user": "jeff"}
```

Both hooks fail open on malformed input. A broken hook should never stop a developer working, and the deny rules below still apply.

---

## 4. Contain: managed settings and AWS guardrails

### Baseline deny rules

[`policies/managed-settings.baseline.json`](policies/managed-settings.baseline.json) denies reads of secrets, writes to shell profiles and credential folders, pipe-to-shell, `ssh`/`scp`/`nc`/`sudo`, and disables permission bypass mode. Deploy it as **managed settings** with your MDM so developers cannot override it:

| OS | Path |
|---|---|
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

### MCP allow and deny lists

[`policies/mcp-policy.example.json`](policies/mcp-policy.example.json) allows named or company-hosted MCP servers and blocks plain-http and public tunnel hosts. Deny always wins over allow.

### Terraform: Bedrock budgets and a least-privilege agent role

[`terraform/`](terraform/) creates:

- a **monthly** Amazon Bedrock budget (alerts at 80% actual and 100% forecast), plus a **daily** budget as a circuit breaker, because a runaway agent loop can burn a month's budget in an afternoon;
- an **IAM role for agents** that can only invoke the Bedrock inference profiles you approve, explicitly cannot create, update or delete Bedrock resources, and has 1-hour sessions.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # set emails and trusted principals
terraform init && terraform plan
```

---

## Use it inside Claude Code: the `agent-config-review` skill

[`skills/agent-config-review/`](skills/agent-config-review/) packages the scanner as a Claude Code skill. Copy it to `.claude/skills/` and ask *"review the agent configuration in this repo"*. Claude runs the scanner, verifies each finding, and reports fixes without editing anything. The skill explicitly tells Claude to treat config text as data: in testing, it reported a planted *"ignore previous instructions"* line as an injection attempt instead of following it.

---

## Repository layout

```text
scanner/agent_config_scan.py     scanner CLI (text, JSON, SARIF)
action.yml                       GitHub Action wrapper
hooks/                           PreToolUse secret blocker, PostToolUse audit log
policies/                        managed-settings baseline, MCP policy, hooks registration
skills/agent-config-review/      Claude Code skill
terraform/                       Bedrock budgets + least-privilege agent IAM role
examples/risky-repo              deliberately insecure fixture (do not copy)
examples/clean-repo              hardened fixture
tests/                           pytest suite for scanner and hooks
```

The kit uses its own controls: this repo's [`.claude/settings.json`](.claude/settings.json) registers both hooks and the deny rules, and CI scans the repo with the scanner.

## Limitations

- The scanner uses pattern matching. It catches common and careless risks, not a determined attacker who rewords an injection. Treat it as one layer next to code review.
- Hooks protect sessions where they are installed. Managed settings are what make controls non-optional.
- Budgets alert; they do not stop spend on their own. For hard per-user caps, put a gateway with spend limits in front of Bedrock.

## Roadmap

- [ ] Rules for `AGENTS.md` and other agents' config formats
- [ ] Ship the audit log straight to CloudWatch Logs
- [ ] pre-commit hook packaging

## Background

I built this after hands-on time running Claude Code on Amazon Bedrock with SSO-based access, per-group model restrictions, spend limits and usage telemetry. Seeing those controls work, and seeing which ones only an administrator could set, made the gap clear: the config files inside each repository needed guardrails of their own. Everything here is my own work, built from the public [Claude Code documentation](https://docs.claude.com/en/docs/claude-code/overview) and [AWS documentation](https://docs.aws.amazon.com/bedrock/).

## License

MIT, see [LICENSE](LICENSE). Built by [Jeff Mbita](https://jeff-mbita-portfolio.vercel.app/), Cloud Solutions Architect.
