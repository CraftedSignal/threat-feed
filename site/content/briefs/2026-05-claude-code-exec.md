---
title: claude-code-cache-fix Local Code Execution via Python Injection (CVE-2026-45136)
slug: 2026-05-claude-code-exec
description: A vulnerability exists in claude-code-cache-fix versions 3.5.0 and 3.5.1 where the `tools/quota-statusline.sh` script interpolates Claude Code's hook stdin payload directly into a Python triple-quoted string literal, allowing local code execution via Python triple-quote injection (CVE-2026-45136).
date: "2026-05-13T15:37:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-execution
  - injection
  - linux
vendors:
  - cnighswonger
products:
  - claude-code-cache-fix
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-g3xq-3gmv-qq8g
  - https://github.com/cnighswonger/claude-code-cache-fix/issues/108
rules:
  - title: Detect Python Code Injection via quota-statusline.sh (CVE-2026-45136)
    description: Detects CVE-2026-45136 exploitation — detects shell commands invoking python with code injection via stdin
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect quota-statusline.sh Execution
    description: Detects the execution of the quota-statusline.sh script.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Claude Code versions 3.5.0 and 3.5.1 are vulnerable to local code execution via Python injection. The vulnerability lies in the `tools/quota-statusline.sh` script, which is recommended in the v3.5.0 README for wiring into the `statusLine` configuration. The script directly interpolates Claude Code's hook stdin payload into a Python triple-quoted string literal. By crafting a malicious directory name containing the sequence `'''`, an attacker can prematurely close the string literal and inject arbitrary Python code into the user's Claude Code process. This code executes with the user's privileges, allowing access to sensitive data and resources. The vulnerability was reported on 2026-05-07 and patched in version 3.5.2, released on the same day.

## Attack Chain

1. A malicious actor crafts a directory name containing the string `'''` followed by arbitrary Python code and another `'''` to close the string.
2. The attacker delivers the hostile directory to the victim's filesystem via any means (e.g., `git clone`, archive extraction, npm package installation, downloaded zip file).
3. The victim has `tools/quota-statusline.sh` configured as the `statusLine` hook in their Claude Code settings as recommended.
4. The victim navigates into the directory containing the hostile path using the `cd` command in their shell. This can also occur if a project or workspace is opened from the hostile path.
5. Claude Code's statusline hook is triggered upon every statusline redraw, which happens frequently.
6. The `tools/quota-statusline.sh` script executes, interpolating the user-controlled directory path into the Python command.
7. The malicious payload injected via the directory name is executed as Python code within the context of the user's Claude Code process.
8. The attacker gains local code execution with the privileges of the user running Claude Code, allowing them to access files, SSH keys, and other sensitive data.

## Impact

Successful exploitation of this vulnerability leads to local code execution with the privileges of the user running Claude Code. An attacker can gain access to the user's files, SSH keys, and other sensitive credentials. This can lead to complete compromise of the user's local environment and potentially lateral movement to other systems if credentials are reused. Users who followed the recommended setup instructions in the v3.5.0 README are particularly at risk.

## Recommendation

- Upgrade to claude-code-cache-fix version 3.5.2 or later to remediate CVE-2026-45136.
- Disable the statusline by removing the `statusLine` entry from `~/.claude/settings.json` as a temporary workaround.
- Deploy the Sigma rule "Detect Python Code Injection via quota-statusline.sh (CVE-2026-45136)" to your SIEM to detect potential exploitation attempts.
