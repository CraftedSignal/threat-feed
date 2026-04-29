---
title: PraisonAI UI Hardcoded Approval Mode Leads to Remote Code Execution
slug: 2024-01-09-praisonai-rce
description: A vulnerability in PraisonAI allows authenticated users to execute arbitrary shell commands due to a hardcoded approval setting in the Chainlit UI modules, overriding administrator configurations and bypassing intended approval gates; insufficient command sanitization allows for destructive command execution, leading to confidentiality breach, integrity compromise, and availability impact on the server.
date: "2026-04-10T19:25:49Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - rce
  - command-injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qwgj-rrpj-75xm
rules:
  - title: Detect Suspicious PraisonAI Command Execution
    description: Detects suspicious command execution by PraisonAI, focusing on commands like curl or wget used for potential data exfiltration or backdoor installation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Outbound Connection from PraisonAI
    description: Detects suspicious outbound network connections originating from the PraisonAI process, indicating potential data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

PraisonAI is vulnerable to remote code execution due to a misconfiguration in the Chainlit UI modules (`chat.py` and `code.py`). Specifically, the application hardcodes `config.approval_mode = "auto"`, effectively disabling the intended human-in-the-loop approval mechanism for ACP tool executions, even when administrators configure the application to require manual approval. This override occurs after the application loads administrator configurations from the `PRAISON_APPROVAL_MODE` environment variable. Consequently, an authenticated user, including those using default credentials, can instruct the LLM agent to execute arbitrary single-command shell operations on the server without any approval prompt, subject only to the PraisonAI process’s OS-level permissions. The vulnerability affects PraisonAI versions prior to 4.5.128.

## Attack Chain

1. An attacker authenticates to the PraisonAI UI using valid credentials (default admin/admin if unchanged).
2. The attacker crafts a chat message that instructs the LLM agent to execute a shell command via the `acp_execute_command` function.
3. The LLM agent parses the message and prepares the command for execution.
4. Due to the hardcoded `approval_mode = "auto"` in `chat.py` or `code.py`, the command bypasses the intended approval process in `agent_tools.py`.
5. The `subprocess.run()` function in `action_orchestrator.py` executes the attacker-controlled command with `shell=True`.
6. The command executes with the permissions of the PraisonAI process.
7. The result of the command execution is returned to the attacker via the chat interface.
8. The attacker leverages this vulnerability to achieve code execution, data exfiltration, or other malicious objectives.

## Impact

Successful exploitation allows an authenticated user to execute arbitrary shell commands on the server hosting PraisonAI. This can lead to:

- **Confidentiality breach:** Read sensitive files accessible to the process (e.g., `/etc/passwd`, application secrets).
- **Integrity compromise:** Modify or delete files, install backdoors.
- **Availability impact:** Kill processes, consume resources, delete data.
- **Administrator control undermined:** The hardcoded `approval_mode` silently overrides administrator-configured settings, creating a false sense of security.
- **Prompt injection vector:** Malicious content could trigger command execution through auto-approved tools without direct user intent, especially through external sources like web searches or uploaded files.

The vulnerable versions are PraisonAI versions prior to 4.5.128.

## Recommendation

- **Upgrade PraisonAI:** Upgrade to version 4.5.128 or later to patch the vulnerability.
- **Apply Code-Level Fix:** If upgrading is not immediately feasible, manually remove the hardcoded override in `chat.py` and `code.py` as described in the advisory.
- **Implement Allowlisting:** Strengthen command sanitization by implementing an allowlist approach instead of a blocklist in the `_sanitize_command()` function as described in the advisory.
- **Monitor Process Creation:** Deploy the Sigma rule "Detect Suspicious PraisonAI Command Execution" to detect exploitation attempts.
- **Monitor Network Connections:** Deploy the Sigma rule "Detect Suspicious Outbound Connection from PraisonAI" to identify potential data exfiltration attempts.
- **Review Authentication:** Ensure strong passwords are in use and consider multi-factor authentication to mitigate risks from compromised credentials.
