---
title: gemini-mcp-tool Vulnerable to OS Command Injection and File Exfiltration (CVE-2026-0755)
slug: 2026-06-gemini-mcp-tool-rce-exfiltration
description: A critical vulnerability, CVE-2026-0755, in npm's gemini-mcp-tool package allows for OS command injection on Windows systems due to improper handling of unquoted cmd.exe metacharacters, and arbitrary local file exfiltration via the @file parser when processing untrusted prompt input, leading to potential remote code execution and sensitive data compromise.
date: "2026-06-18T20:49:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - file-exfiltration
  - npm
  - cli-tool
  - web-vulnerability
products:
  - gemini-mcp-tool (>= 1.1.2, < 1.1.6)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-4h5r-5jm8-jxjm
rules:
  - title: Detects CVE-2026-0755 Exploitation - Suspicious Node.js Child Process Execution
    description: Detects attempts to exploit CVE-2026-0755 via OS command injection, where the gemini-mcp-tool (likely running via node.exe) spawns cmd.exe or powershell.exe with arguments containing shell metacharacters. This indicates potential remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-0755 Exploitation - Suspicious @file-like Path Access
    description: Detects potential attempts to exploit CVE-2026-0755 via file exfiltration by monitoring for suspicious access patterns to sensitive system files, especially those referenced with an '@' prefix which could indicate abuse of the gemini-mcp-tool's @file parser.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - exfiltration
    techniques:
      - T1005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A critical vulnerability, tracked as CVE-2026-0755, exists in versions 1.1.2 through 1.1.5 of the npm package `gemini-mcp-tool`. This flaw allows an attacker to achieve OS command injection on Windows systems by exploiting improper handling of unquoted `cmd.exe` metacharacters when the tool processes untrusted prompt input. Simultaneously, the tool's `@file` parser can be abused to read and exfiltrate arbitrary local files from the host system, including sensitive configuration files like `/etc/passwd` or private keys such as `~/.ssh/id_rsa`. The vulnerability stems from insufficient sanitization and quoting of user-supplied prompt data before it is processed by the tool or passed to the underlying operating system. This could lead to full system compromise or extensive data theft, affecting organizations utilizing this specific CLI tool in their development or operational workflows. The issue was addressed in version 1.1.6, which includes hardened Windows `cmd.exe` argument quoting and restricts `@file` references to the working directory.

## Attack Chain

1.  **Attacker Crafts Malicious Prompt**: An attacker creates a specially crafted prompt input containing `cmd.exe` metacharacters (e.g., `&`, `|`, `&&`) for OS command injection or `@file` references (e.g., `@/etc/passwd`) for file exfiltration.
2.  **User Executes Vulnerable Tool**: The `gemini-mcp-tool` (versions 1.1.2 to 1.1.5), often run via `node.exe` as an npm package, is executed with the attacker-controlled malicious prompt as an argument.
3.  **Improper Argument Handling (Windows)**: On Windows systems, the vulnerable tool processes the prompt without adequately quoting the `cmd.exe` metacharacters, leading to them being interpreted as separate commands when passed to the underlying shell.
4.  **OS Command Injection**: The `gemini-mcp-tool` or its child process (e.g., `node.exe` spawning `cmd.exe`) executes the injected OS commands, allowing the attacker to run arbitrary commands on the system with the privileges of the tool.
5.  **Sensitive File Access (File Exfiltration)**: Alternatively, if the prompt includes `@file` references to sensitive paths (e.g., `@C:\Windows\System32\drivers\etc\hosts` or `@/etc/passwd`), the `gemini-mcp-tool`'s internal parser will attempt to read these files from the local filesystem, bypassing intended directory restrictions.
6.  **Data Exfiltration / Remote Code Execution**: The content of the accessed sensitive files can be retrieved or exfiltrated by the attacker, or the successful command injection grants the attacker remote code execution capabilities, enabling further compromise, persistence, or data theft.

## Impact

Successful exploitation of CVE-2026-0755 allows for critical impact, including full system compromise through remote code execution on affected Windows systems. Attackers can execute arbitrary commands, install malware, create new user accounts, or modify system configurations. Furthermore, the ability to exfiltrate arbitrary local files poses a severe risk of sensitive data exposure, including credentials, private keys, intellectual property, and internal system configurations. This could lead to significant financial losses, reputational damage, and regulatory penalties. The nature of the package suggests potential impact across development environments, CI/CD pipelines, or systems where this CLI tool is used for Gemini-related operations.

## Recommendation

*   **Patch CVE-2026-0755 immediately** by upgrading `gemini-mcp-tool` to version 1.1.6 or higher to address both OS command injection and file exfiltration vulnerabilities.
*   **Enable Sysmon process_creation logging** on all Windows endpoints and servers to activate the rules provided in this brief.
*   **Deploy the Sigma rules in this brief** to your SIEM and tune for your environment to detect suspicious command execution patterns involving `node.exe` or `cmd.exe` and attempts to read sensitive files.
*   **Implement strict input validation** for any applications or scripts that pass user-controlled input directly to the `gemini-mcp-tool` CLI.
