# claude-code-governance-kit

Security tooling for teams adopting AI coding agents.

## Commands
- `python3 -m pytest -q` runs all tests
- `python3 scanner/agent_config_scan.py . --exclude examples` scans this repo

## Rules
- `examples/risky-repo` is a deliberately insecure test fixture. Never copy its settings anywhere.
- Every new scanner rule needs a test in `tests/test_scanner.py` and a row in the README rule table.
- Hooks must exit 0 on malformed input. Only the secret-access hook may exit 2 (block).
