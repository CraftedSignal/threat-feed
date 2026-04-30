---
title: Modelscope Agentscope Code Injection Vulnerability (CVE-2026-6603)
slug: 2026-04-agentscope-code-injection
description: A code injection vulnerability exists in modelscope agentscope up to version 1.0.18, specifically affecting the execute_python_code/execute_shell_command functions, allowing for remote code execution.
date: "2026-04-20T05:16:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - remote-code-execution
  - agentscope
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6603
  - https://gist.github.com/YLChen-007/c084d69aaeda6729f3988603f2b0ce6e
  - https://vuldb.com/vuln/358238
rules:
  - title: Detect Suspicious Process Execution from Agentscope
    description: Detects process execution originating from the agentscope application server, which may indicate exploitation of CVE-2026-6603.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Requests to Agentscope Code Execution Endpoints
    description: Detects suspicious HTTP requests targeting the execute_python_code or execute_shell_command endpoints in Agentscope, indicating potential code injection attempts (CVE-2026-6603).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical code injection vulnerability, identified as CVE-2026-6603, affects modelscope agentscope versions up to 1.0.18. The vulnerability resides within the `execute_python_code` and `execute_shell_command` functions in the `src/AgentScope/tool/_coding/_python.py` file. This flaw allows an attacker to inject arbitrary code, leading to potential remote code execution on the affected system. A public exploit is available, increasing the risk of widespread exploitation. The vendor was contacted but has not responded to the disclosure. This vulnerability poses a significant threat to systems running vulnerable versions of agentscope, potentially leading to compromise and unauthorized access.

## Attack Chain

1.  An attacker identifies a vulnerable instance of modelscope agentscope running a version up to 1.0.18.
2.  The attacker crafts a malicious request targeting the `execute_python_code` or `execute_shell_command` function.
3.  The malicious request injects arbitrary code into the vulnerable function's input.
4.  The application processes the injected code without proper sanitization or validation.
5.  The injected code is executed by the system, potentially allowing the attacker to execute arbitrary commands.
6.  The attacker leverages the executed code to gain further access to the system or network.
7.  The attacker installs malware, establishes persistence, or exfiltrates sensitive data.

## Impact

Successful exploitation of CVE-2026-6603 can result in arbitrary code execution on the affected system. This can lead to complete system compromise, data breaches, and unauthorized access to sensitive information. While the exact number of victims is currently unknown, the availability of a public exploit makes widespread exploitation highly probable. Organizations using modelscope agentscope are at risk and should take immediate action to mitigate this vulnerability.

## Recommendation

*   Upgrade modelscope agentscope to a patched version beyond 1.0.18 to remediate the vulnerability (CVE-2026-6603).
*   Implement the provided Sigma rule to detect suspicious process execution originating from the agentscope application server.
*   Monitor web server logs for unusual requests targeting the `execute_python_code` or `execute_shell_command` endpoints (webserver log source).
