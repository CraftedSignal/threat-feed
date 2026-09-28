---
title: Command Injection in code-ollama grep_search Tool
slug: 2026-09-code-ollama-command-injection
description: A command injection vulnerability in the code-ollama grep_search tool allows unauthorized arbitrary command execution by failing to sanitize shell metacharacters in attacker-controlled arguments.
date: "2026-09-28T16:17:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-execution
  - command-injection
  - supply-chain
vendors:
  - ai-action
products:
  - code-ollama (<= 0.36.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The tool executes a shell command string via child_process.exec, causing /bin/sh to interpret the string.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-456v-xq2p-r4cj
action_plan:
  priority: elevated
  owners:
    - SOC
    - Security Engineering
  immediate_actions:
    - action: Review and restrict usage of code-ollama --trust flag in production or sensitive environments.
      owner: Security Engineering
      due: 24h
      evidence: The advisory states that Plan mode auto-execution provides a no-interaction exploitation path.
  mitigation_plan:
    - priority: immediate
      action: Monitor for `code-ollama` process children spawning shells or unusual file creation in /tmp/.
      owner: SOC
      addresses: CWE-78 Command Injection
      evidence: PoC demonstrates creation of files in /tmp/ during exploitation.
---

The code-ollama utility (version 0.36.0 and earlier) contains a command injection vulnerability in the grep_search tool, documented as CWE-78. The root cause is improper input sanitization when constructing shell commands for the ripgrep (rg) binary. The application only escapes backslashes and double quotes while failing to neutralize shell substitution sequences such as $() and backticks. 

When code-ollama processes a malicious tool call, it assembles an command string and passes it to child_process.exec(), which interprets the entire string via /bin/sh. Because grep_search is designated as a read-only tool, it executes automatically in Plan mode without requesting user authorization. A malicious or compromised Ollama server can exploit this by delivering a specially crafted pattern argument to the client. This vulnerability effectively permits arbitrary command execution under the security context of the user running the code-ollama CLI, presenting high risks to confidentiality, integrity, and availability.

## Attack Chain

1. The user executes `code-ollama run`, initiating an unencrypted connection to a malicious or compromised Ollama server.
2. The attacker-controlled server sends a specifically crafted tool call response containing an injection payload in the `pattern` argument (e.g., `$(id > /tmp/poc)`).
3. The `code-ollama` client receives the response, and `dispatcher.ts` routes the `grep_search` call to the filesystem utility.
4. The `grep.ts` module performs incomplete sanitization, stripping only `\` and `"` characters while leaving the shell substitution sequence `$()` intact.
5. The application assembles the final command string: `rg --line-number --no-heading --smart-case "$(id > /tmp/poc)" "/tmp"`.
6. The `execShell()` function invokes `child_process.exec()`, handing the string to `/bin/sh`.
7. The shell expands the `$()` substitution, executing the attacker's embedded `id` command before starting the `rg` process.
8. The attacker achieves arbitrary code execution with the permissions of the local user process.

## Impact

Successful exploitation allows for full command execution on the host machine. An attacker can exfiltrate sensitive files (including source code and SSH keys), plant backdoors, or alter the system environment. Because the exploit occurs silently through the auto-execution of read-only tools in Plan mode, victims may not realize their session has been compromised. The risk is significant for developers and CI/CD pipelines running code-ollama in trusted environments.

## Recommendation

1. Upgrade code-ollama to a patched version once available that replaces `execShell()` with `execFile()` to eliminate shell interpretation of arguments.
2. Until a patch is deployed, avoid using the `--trust` flag or executing code-ollama against untrusted or unverified Ollama server endpoints.
3. Audit environments where `code-ollama` is utilized, specifically monitoring for unexpected outbound network connections from the CLI or sub-processes initiated by `code-ollama`.
4. Apply host-based EDR/monitoring to alert on suspicious process lineage where `code-ollama` (or its child processes) spawns shell interpreters like `/bin/sh` or `cmd.exe` with command-line arguments containing `$` or `(` characters.
