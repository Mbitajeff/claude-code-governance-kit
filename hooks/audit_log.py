#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Jeff Mbita. https://github.com/Mbitajeff/claude-code-governance-kit
"""Claude Code PostToolUse hook: append an audit record for every agent action that changes things.

Writes one JSON line per Edit/Write/MultiEdit/Bash call: timestamp, session, tool, target and cwd.
File contents and command output are never logged, only what was touched.

Log location: $AGENT_AUDIT_LOG, or ~/.claude/audit/agent-audit.jsonl by default.
Ship the file to your SIEM or CloudWatch Logs with your normal log agent.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_COMMAND_CHARS = 300


def record_for(event: dict) -> dict:
    tool_input = event.get("tool_input", {}) or {}
    target = tool_input.get("file_path") or tool_input.get("notebook_path")
    command = tool_input.get("command")
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": event.get("session_id"),
        "event": event.get("hook_event_name", "PostToolUse"),
        "tool": event.get("tool_name"),
        "target": target,
        "command": command[:MAX_COMMAND_CHARS] if isinstance(command, str) else None,
        "cwd": event.get("cwd"),
        "user": os.environ.get("USER") or os.environ.get("USERNAME"),
    }


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    log_path = Path(os.environ.get("AGENT_AUDIT_LOG", Path.home() / ".claude" / "audit" / "agent-audit.jsonl"))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record_for(event)) + "\n")
    except OSError as exc:
        print(f"audit_log: could not write {log_path}: {exc}", file=sys.stderr)
    return 0  # auditing must never block the developer


if __name__ == "__main__":
    sys.exit(main())
