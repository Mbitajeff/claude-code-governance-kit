# Reference: why each rule matters

| ID | Severity | Rule | Why it matters |
|---|---|---|---|
| ACS001 | High | Prompt-injection phrase | Agent config is loaded into context every session, so injected instructions persist silently. |
| ACS002 | High | Remote code piped to a shell | Runs unreviewed code from the internet. |
| ACS003 | High | Permission bypass | Removes the human approval step for every tool call. |
| ACS004 | High | Blanket allow rule | Auto-approves any command, write or fetch. |
| ACS005-007 | High | AWS keys, private keys, API tokens | Config files are committed and shared. |
| ACS008 | Medium | Plain http to a non-local host | Traffic can be read or altered in transit. |
| ACS009 | Medium | Hook making network calls | Hooks run automatically on every matching tool call, so they are a quiet exfiltration path. |
| ACS010 | Low | Invalid settings JSON | Broken settings silently do not load, including your deny rules. |
| ACS101-103 | Low | Missing deny rule for .env, ~/.ssh, ~/.aws | Cheap baseline that blocks the most common accidental exposure. |
