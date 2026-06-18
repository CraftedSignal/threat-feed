---
title: PraisonAI `multiedit` Tool Vulnerability Allows Arbitrary File Read/Write and RCE
slug: 2026-06-praisonai-multiedit-rce
description: A critical vulnerability in PraisonAI's `multiedit` tool, affecting versions prior to 4.6.61, enables threat actors to achieve arbitrary file read and write capabilities by influencing LLM agent tool arguments, leading to sensitive data exfiltration and potential remote code execution.
date: "2026-06-18T14:47:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - LLM
  - AI
  - supply-chain
  - arbitrary-file-read
  - arbitrary-file-write
  - path-traversal
  - RCE
products:
  - praisonai (< 4.6.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-29w3-p9w9-wc47
rules:
  - title: Detect PraisonAI `multiedit` Tool Invocation with Sensitive Paths
    description: Detects Python processes that appear to be invoking the PraisonAI `multiedit` tool with arguments targeting sensitive file paths, indicating attempted exploitation of GHSA-29w3-p9w9-wc47.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
      - T1083
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Python Process Writing to Sensitive User/System Files
    description: Detects Python processes attempting to write to critical system or user configuration files, which could indicate exploitation of arbitrary file write vulnerabilities like GHSA-29w3-p9w9-wc47.
    platform: sigma
    severity: high
    tactics:
      - impact
      - persistence
    techniques:
      - T1098
      - T1485
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Python Process Reading Highly Sensitive Files
    description: Detects Python processes attempting to read highly sensitive system or user files, which could indicate exploitation of arbitrary file read vulnerabilities like GHSA-29w3-p9w9-wc47.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1003
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 3
---

A severe arbitrary file read and write vulnerability has been discovered in the `multiedit` tool within the PraisonAI framework, impacting versions prior to 4.6.61. This flaw, tracked as GHSA-29w3-p9w9-wc47, arises from a complete lack of path validation, workspace boundary checks, or protected path guards when the `filepath` parameter is used with `open()` for both read and write operations. Threat actors can exploit this by crafting malicious prompts, user inputs in chatbots, or YAML workflow configurations that influence an AI agent's arguments to the `multiedit` tool. This allows for the exfiltration of sensitive information, such as SSH keys and cloud credentials, and the overwrite of critical system or application files, potentially leading to privilege escalation and remote code execution on affected systems.

## Attack Chain

1.  **Initial Access**: A threat actor crafts malicious input (e.g., a specially designed prompt, a user message in a chatbot, or a YAML workflow configuration) to influence the arguments of an AI agent utilizing the PraisonAI framework.
2.  **Agent Interaction**: The AI agent, operating with the vulnerable PraisonAI `multiedit` tool, receives and processes the attacker-controlled input, which specifies a malicious `filepath` parameter.
3.  **Tool Execution**: The AI agent invokes the `multiedit` tool (e.g., via `python -c "import praisonai.tools.multiedit; multiedit('/etc/shadow', ...)"`) with the unvalidated `filepath`.
4.  **Arbitrary File Read**: The `multiedit` tool, due to missing path validation, attempts to read content from the attacker-specified sensitive file (e.g., `/etc/shadow`, `~/.ssh/id_rsa`) and leaks it via the `dry_run` output or other return mechanisms.
5.  **Arbitrary File Write**: Simultaneously or subsequently, the attacker can use the `multiedit` tool to write to or overwrite critical system or user configuration files (e.g., `~/.bashrc`, `~/.ssh/authorized_keys`, web application source code).
6.  **Privilege Escalation / Persistence**: By writing to files like `authorized_keys` or shell startup scripts, the attacker establishes persistence, gains elevated privileges, or achieves remote code execution upon the next login or script execution.
7.  **Impact**: The attacker exfiltrates sensitive data (step 4) or executes arbitrary commands (step 6), leading to full system compromise, data destruction, or further network lateral movement.

## Impact

This vulnerability poses a critical risk to PraisonAI deployments, particularly where AI agents interact with user-provided input or process untrusted configurations with `auto_approve_tools=True`. Successful exploitation allows attackers, who can influence the `filepath` parameter, to read any file accessible by the PraisonAI process user, including highly sensitive data like SSH private keys (`~/.ssh/id_rsa`), AWS credentials (`~/.aws/credentials`), `/etc/shadow`, and `.env` files. Furthermore, attackers can overwrite arbitrary files, enabling various destructive outcomes such as defacing web applications, injecting malicious scripts into startup files (`.bashrc`), or gaining persistent access and privilege escalation by writing to `authorized_keys`. The broad impact on confidentiality, integrity, and availability makes this a severe threat for affected organizations.

## Recommendation

*   Upgrade the `praisonai` package to version `4.6.61` or later immediately to remediate the GHSA-29w3-p9w9-wc47 vulnerability.
*   Deploy the provided Sigma rules to your SIEM for detection of suspicious Python activity targeting sensitive files.
*   Ensure Sysmon process-creation and file-event logging is enabled on systems running PraisonAI agents to activate the rules above.
*   If possible, configure PraisonAI agents to require explicit approval for tool usage (e.g., using `@require_approval(risk_level="high")` on sensitive tools) instead of `auto_approve_tools=True`.
