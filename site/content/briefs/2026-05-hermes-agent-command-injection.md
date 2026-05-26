---
title: NousResearch hermes-agent OS Command Injection Vulnerability (CVE-2026-9367)
slug: 2026-05-hermes-agent-command-injection
description: NousResearch hermes-agent up to version 5157f5427f19488b31c6fdebbacd15d798ce7f63 is vulnerable to OS command injection (CVE-2026-9367) in the `detect_dangerous_command` function allowing a remote attacker to execute arbitrary commands.
date: "2026-05-26T13:46:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - cve
vendors:
  - NousResearch
products:
  - hermes-agent
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9367
    cvss: 7.3
    epss: 0.01021
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9367
  - https://gist.github.com/YLChen-007/75fb10319693e86106ced2ef3a472c80
  - https://vuldb.com/submit/812228
  - https://vuldb.com/vuln/365330
  - https://vuldb.com/vuln/365330/cti
rules:
  - title: Detect Hermes-Agent Command Injection via detect_dangerous_command
    description: Detects CVE-2026-9367 exploitation — Attempts to exploit command injection in hermes-agent's detect_dangerous_command function.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Hermes-Agent Command Injection via detect_dangerous_command - POST
    description: Detects CVE-2026-9367 exploitation — Attempts to exploit command injection in hermes-agent's detect_dangerous_command function via POST requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability, identified as CVE-2026-9367, exists in NousResearch hermes-agent up to version 5157f5427f19488b31c6fdebbacd15d798ce7f63. The vulnerability resides within the `detect_dangerous_command` function located in the `tools/approval.py` file of the `terminal_tool` component. This flaw enables a remote attacker to inject arbitrary operating system commands. Publicly available exploits exist, increasing the risk of exploitation. The vendor was notified about the vulnerability but has not responded. This vulnerability poses a significant risk to systems running vulnerable versions of hermes-agent, potentially allowing for complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable instance of NousResearch hermes-agent running a version up to 5157f5427f19488b31c6fdebbacd15d798ce7f63.
2.  The attacker crafts a malicious input designed to be processed by the `detect_dangerous_command` function.
3.  The attacker sends this crafted input to the vulnerable `terminal_tool` component.
4.  The `detect_dangerous_command` function fails to properly sanitize the input, allowing the injection of OS commands.
5.  The injected OS command is executed by the system with the privileges of the hermes-agent process.
6.  The attacker gains arbitrary code execution on the target system.
7.  The attacker may then install malware, exfiltrate sensitive data, or pivot to other systems within the network.

## Impact

Successful exploitation of CVE-2026-9367 allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system. This can lead to a complete compromise of the system, including the theft of sensitive information, installation of malware, and potential lateral movement within the network. Given the nature of the hermes-agent as an agent, this vulnerability could potentially expose numerous systems if successfully exploited.

## Recommendation

*   Apply any available patches or updates provided by NousResearch to address CVE-2026-9367.
*   Monitor network traffic for suspicious commands being sent to systems running hermes-agent. Deploy the provided Sigma rule `Detect Hermes-Agent Command Injection via detect_dangerous_command` to identify command injection attempts.
*   Implement input validation and sanitization measures within the `detect_dangerous_command` function to prevent OS command injection.
*   Review and restrict the permissions of the hermes-agent process to minimize the impact of successful exploitation.
