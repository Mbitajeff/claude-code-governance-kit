#!/usr/bin/env python3
"""agent-config-scan: find risky AI coding agent configuration.

Scans CLAUDE.md, AGENTS.md, .claude/** (settings, skills, commands, hooks) and MCP config files.

Usage:
  agent_config_scan.py [PATH] [--format text|json|sarif] [--output FILE] [--fail-on high|medium|low|none]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__version__ = "0.1.0"

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    pattern: re.Pattern
    fix: str


RULES = [
    Rule("ACS001", "high", "Prompt-injection phrase in agent instructions",
         re.compile(r"ignore (all )?(previous|prior|above) instructions|do not (tell|inform|alert) the user"
                    r"|disregard (your|the|all) (rules|guidelines|instructions)|without (asking|telling) the user", re.I),
         "Remove the instruction. Agent config is loaded into every session, so injected text persists silently."),
    Rule("ACS002", "high", "Remote code piped straight into a shell",
         re.compile(r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
         "Download, verify a checksum or signature, then run. Or use a package manager."),
    Rule("ACS003", "high", "Permission checks bypassed",
         re.compile(r"bypassPermissions|dangerously-skip-permissions"),
         "Use the default permission mode. Enforce disableBypassPermissionsMode in managed settings."),
    Rule("ACS004", "high", "Blanket allow rule auto-approves any command or write",
         re.compile(r'"(Bash|Write|Edit|WebFetch)(\(\*\))?"'),
         "Replace with narrow rules, e.g. Bash(npm run test:*)."),
    Rule("ACS005", "high", "Possible AWS access key",
         re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
         "Remove and rotate the key. Use IAM roles or a secrets manager."),
    Rule("ACS006", "high", "Private key material",
         re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
         "Remove and rotate the key."),
    Rule("ACS007", "high", "Possible API token",
         re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-[A-Za-z0-9_-]{20,}|xox[bp]-[A-Za-z0-9-]{20,})\b"),
         "Remove and rotate the token. Reference it from the environment or a secrets manager."),
    Rule("ACS008", "medium", "Plain http to a non-local host",
         re.compile(r"http://(?!localhost\b|127\.0\.0\.1\b|\[::1\])[\w.-]+"),
         "Use https so traffic cannot be read or altered in transit."),
    Rule("ACS009", "medium", "Hook or command makes network calls",
         re.compile(r'"command"\s*:\s*"[^"]*\b(curl|wget|nc|ncat)\b'),
         "Hooks run automatically on every matching tool call. Confirm the destination and why it is needed."),
]

# (suggested rule, what it protects, regex that recognises an equivalent deny rule)
BASELINE_DENY = {
    "ACS101": ("Read(**/.env*)", "environment files", re.compile(r"^Read\([^)]*\.env")),
    "ACS102": ("Read(~/.ssh/**)", "SSH keys", re.compile(r"^Read\([^)]*\.ssh")),
    "ACS103": ("Read(~/.aws/**)", "AWS credentials", re.compile(r"^Read\([^)]*\.aws")),
}

TARGET_GLOBS = ["CLAUDE.md", "**/CLAUDE.md", "AGENTS.md", ".claude/**/*", ".mcp.json", "**/*.mcp.json"]
TEXT_SUFFIXES = {".md", ".json", ".yaml", ".yml", ".sh", ".py", ".js", ".ts", ""}
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build"}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    line: int
    snippet: str
    fix: str


def iter_targets(root: Path, exclude: tuple[str, ...] = ()):
    seen = set()
    skip = SKIP_DIRS | set(exclude)
    for pattern in TARGET_GLOBS:
        for p in sorted(root.glob(pattern)):
            if p.is_file() and p.suffix in TEXT_SUFFIXES and not skip & set(p.relative_to(root).parts) and p not in seen:
                seen.add(p)
                yield p


def scan(root: Path, exclude: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    deny_rules: set[str] = set()
    saw_settings = False
    for path in iter_targets(root, exclude):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        file_denies: set[str] = set()
        if path.name.endswith("settings.json"):
            saw_settings = True
            try:
                file_denies = set(json.loads(text).get("permissions", {}).get("deny", []))
                deny_rules |= file_denies
            except (json.JSONDecodeError, AttributeError):
                findings.append(Finding("ACS010", "low", "Settings file is not valid JSON", rel, 1, "",
                                        "Fix the JSON so the settings actually load."))
        for n, line in enumerate(text.splitlines(), 1):
            # A deny rule that names a dangerous pattern is a protection, not a risk.
            if line.strip().rstrip(",").strip('"') in file_denies:
                continue
            for rule in RULES:
                if rule.pattern.search(line):
                    findings.append(Finding(rule.id, rule.severity, rule.title, rel, n, line.strip()[:160], rule.fix))
    if saw_settings:
        for rule_id, (rule, what, covers) in BASELINE_DENY.items():
            if not any(covers.search(d) for d in deny_rules):
                findings.append(Finding(rule_id, "low", f"No deny rule protecting {what}", ".claude/settings.json", 1,
                                        "", f'Add "{rule}" to permissions.deny.'))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line))
    return findings


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "agent-config-scan: no findings"
    out = [f"{'SEVERITY':8} {'RULE':7} {'LOCATION':38} ISSUE"]
    for f in findings:
        out.append(f"{f.severity.upper():8} {f.rule_id:7} {f'{f.path}:{f.line}':38} {f.title}")
        if f.snippet:
            out.append(f"{'':55}  > {f.snippet}")
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    out.append(f"\n{len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
    return "\n".join(out)


def to_sarif(findings: list[Finding]) -> dict:
    rules = [{"id": r.id, "name": r.title, "shortDescription": {"text": r.title}, "help": {"text": r.fix},
              "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]}} for r in RULES]
    rules += [{"id": rid, "name": f"Missing deny rule {rule}", "shortDescription": {"text": f"No deny rule protecting {what}"},
               "help": {"text": f'Add "{rule}" to permissions.deny.'}, "defaultConfiguration": {"level": "note"}}
              for rid, (rule, what, _covers) in BASELINE_DENY.items()]
    results = [{"ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity], "message": {"text": f"{f.title}. Fix: {f.fix}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                    "region": {"startLine": max(f.line, 1)}}}]} for f in findings]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "agent-config-scan", "version": __version__,
                                          "informationUri": "https://github.com/Mbitajeff/claude-code-governance-kit",
                                          "rules": rules}}, "results": results}]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent-config-scan", description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", help="write the report to this file instead of stdout")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "none"], default="high",
                    help="exit 1 if any finding at or above this severity (default: high)")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR",
                    help="directory name to skip (repeatable), e.g. --exclude examples")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        ap.error(f"not a directory: {root}")
    findings = scan(root, tuple(args.exclude))

    if args.format == "json":
        report = json.dumps([asdict(f) for f in findings], indent=2)
    elif args.format == "sarif":
        report = json.dumps(to_sarif(findings), indent=2)
    else:
        report = to_text(findings)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(to_text(findings))
    else:
        print(report)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
