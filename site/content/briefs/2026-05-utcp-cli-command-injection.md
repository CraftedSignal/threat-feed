---
title: utcp-cli Command Injection Vulnerability via Unsanitized Argument Substitution (CVE-2026-45369)
slug: 2026-05-utcp-cli-command-injection
description: The `utcp-cli` package is vulnerable to command injection. The `_substitute_utcp_args` method in `cli_communication_protocol.py` inserts user-controlled values directly into shell command strings without sanitization, allowing an attacker to inject arbitrary shell commands, resulting in full Remote Code Execution. The vulnerability is fixed in version 1.1.2.
date: "2026-05-14T20:56:40Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - command-injection
  - rce
  - utcp-cli
products:
  - utcp-cli
affected_os:
  - linux
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-33p6-5jxp-p3x4
  - CVE-2026-45369
rules:
  - title: Detect utcp-cli Command Injection Attempt via Argument Substitution
    description: Detects potential command injection attempts in `utcp-cli` by monitoring process creations with suspicious arguments that leverage shell metacharacters. Focuses on detecting execution of bash or powershell with arguments indicative of injection attempts related to CVE-2026-45369.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-45369
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect utcp-cli Process Execution with Suspicious Arguments
    description: Detects the execution of processes related to `utcp-cli` with arguments that might indicate command injection attempts, focusing on the presence of specific argument patterns derived from CVE-2026-45369.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-45369
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `utcp-cli` package before version 1.1.2 contains a command injection vulnerability within the `_substitute_utcp_args` method of `cli_communication_protocol.py`. This flaw stems from the direct insertion of user-controlled `tool_args` values into shell command strings without proper sanitization or escaping. Subsequently, these crafted commands are executed using `/bin/bash -c` on Unix-like systems or `powershell.exe -Command` on Windows, enabling a malicious actor to inject arbitrary shell commands. This vulnerability poses a significant risk, as it allows for complete Remote Code Execution (RCE) on the affected host. The issue has been addressed in `utcp-cli` version 1.1.2 by implementing shell-quoting of all substituted values using `shlex.quote` on Unix and PowerShell single-quoted literals on Windows systems, which mitigates the risk of metacharacter injection. The vulnerability was reported by @ZeroXJacks.

## Attack Chain

1. An attacker crafts a malicious payload containing shell metacharacters.
2. The attacker supplies this payload as a value within the `tool_args` dictionary.
3. The vulnerable `_substitute_utcp_args` method substitutes the attacker-controlled value into a command string.
4. Due to the lack of sanitization, the command string now contains the injected shell metacharacters.
5. The command string is embedded within a shell script.
6. The shell script is executed using `/bin/bash -c` or `powershell.exe -Command`.
7. The injected shell metacharacters are interpreted, executing arbitrary commands.
8. The attacker achieves Remote Code Execution on the host system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the host system with the privileges of the `utcp-cli` application. This can lead to complete system compromise, including data exfiltration, malware installation, and denial-of-service. Given the severity and ease of exploitation, any system running a vulnerable version of `utcp-cli` is at critical risk.

## Recommendation

*   Upgrade `utcp-cli` to version 1.1.2 or later to remediate CVE-2026-45369.
*   Deploy the Sigma rule "Detect utcp-cli Command Injection Attempt via Argument Substitution" to your SIEM and tune for your environment.
*   If upgrading is not immediately feasible, restrict or audit user-supplied input to `tool_args` to mitigate the risk of command injection.
