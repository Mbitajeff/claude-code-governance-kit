#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block the agent from reading or writing secret files.

Covers Read/Edit/Write/MultiEdit file paths, Grep/Glob search paths, and Bash commands
that touch secret locations (cat ~/.aws/credentials, cp .env /tmp, etc.).

Claude Code passes the tool call as JSON on stdin. Exit code 2 blocks the call and
sends stderr back to the agent as the reason. Exit code 0 allows it.
"""
from __future__ import annotations

import json
import re
import sys

SECRET_PATTERNS = [
    (re.compile(r"(^|/)\.env(\.[\w.-]+)?$"), "environment file"),
    (re.compile(r"(^|/)\.ssh(/|$)"), "SSH directory"),
    (re.compile(r"(^|/)\.aws/(credentials|config)$"), "AWS credentials"),
    (re.compile(r"(^|/)id_(rsa|ed25519|ecdsa)(\.pub)?$"), "SSH key"),
    (re.compile(r"\.(pem|key|p12|pfx)$"), "private key or certificate"),
    (re.compile(r"(^|/)\.(netrc|npmrc|pypirc)$"), "credential file"),
    (re.compile(r"(^|/)\.docker/config\.json$"), "Docker registry credentials"),
]
ALLOWED_SUFFIXES = (".env.example", ".env.sample", ".env.template")
BASH_SECRET_REFS = re.compile(
    r"(\.env\b(?!\.(example|sample|template))|~/\.ssh|\.ssh/|~/\.aws|\.aws/credentials|id_rsa|id_ed25519|\.pem\b|\.netrc|\.npmrc|\.pypirc)"
)


def check_path(path: str) -> str | None:
    if not path or path.endswith(ALLOWED_SUFFIXES):
        return None
    normalized = path.replace("\\", "/")
    for pattern, label in SECRET_PATTERNS:
        if pattern.search(normalized):
            return label
    return None


def decide(event: dict) -> str | None:
    """Return a block reason, or None to allow."""
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}

    if tool in {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        label = check_path(path)
        if label:
            return f"Blocked {tool} on {path}: it looks like a {label}. Secrets must not enter the agent's context."
    elif tool in {"Grep", "Glob"}:
        target = tool_input.get("path", "") or ""
        label = check_path(target)
        if label:
            return f"Blocked {tool} in {target}: it looks like a {label}."
    elif tool == "Bash":
        command = tool_input.get("command", "") or ""
        match = BASH_SECRET_REFS.search(command)
        if match:
            return (f"Blocked shell command referencing '{match.group(0)}'. "
                    "Read secrets from your secrets manager at runtime instead of through the agent.")
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # never break the session on malformed input
    reason = decide(event)
    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
