# Security policy

This project is security tooling, so reports are taken seriously and handled privately.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Use GitHub's private reporting instead: go to the **Security** tab of this repository and click **Report a vulnerability**. Include:

- what you found and where (file and line, or rule ID)
- how to reproduce it
- the impact, for example a bypass of a hook or a detection rule

You will get an acknowledgement within 5 working days and a status update at least every 14 days until it is resolved. Valid reports are credited in the changelog unless you prefer to stay anonymous.

## In scope

- A way to read or write secrets that `hooks/block_secret_access.py` should block
- A way to make `hooks/audit_log.py` record file contents or silently skip an action
- A scanner crash or hang on crafted input
- Anything in `terraform/` that grants more access than documented

A config pattern the scanner does not detect is a feature request, not a vulnerability. Open a normal issue for it.

## Supported versions

Only the latest release receives fixes.

## Verifying your copy

Each release lists SHA-256 checksums in [`CHECKSUMS.txt`](CHECKSUMS.txt). Copies distributed outside this repository, such as skill marketplace listings, should match them. If they do not, treat the copy as untrusted and report it.

```bash
sha256sum -c CHECKSUMS.txt          # Linux / Git Bash
Get-FileHash scanner/agent_config_scan.py -Algorithm SHA256   # PowerShell
```
