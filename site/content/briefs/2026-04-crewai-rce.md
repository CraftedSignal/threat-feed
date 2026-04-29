---
title: CrewAI Vulnerabilities Allow Remote Code Execution
slug: 2026-04-crewai-rce
description: Multiple vulnerabilities in CrewAI, an open-source multi-agent orchestration framework, can be exploited by attackers through prompt injection to execute arbitrary code and perform other malicious activities, potentially leading to system compromise.
date: "2026-04-01T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - ai
  - rce
  - prompt-injection
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-2275
  - id: CVE-2026-2286
  - id: CVE-2026-2287
  - id: CVE-2026-2285
references:
  - https://www.securityweek.com/crewai-vulnerabilities-expose-devices-to-hacking/
rules:
  - title: Detect CrewAI Sandbox Escape via Arbitrary File Read
    description: Detects attempts to read arbitrary files on the server via the CrewAI JSON loader tool vulnerability (CVE-2026-2285), indicating a potential sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect CrewAI SSRF Attempts
    description: Detects potential Server-Side Request Forgery (SSRF) attempts related to CVE-2026-2286 by monitoring network connections initiated by CrewAI processes to internal or cloud services.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect SandboxPython Fallback
    description: Detects the fallback to SandboxPython due to Docker inaccessibility, which may indicate CVE-2026-2275 exploitation
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

CrewAI, an open-source multi-agent orchestration framework based on Python, is vulnerable to a chain of exploits that can lead to remote code execution. Discovered by Yarden Porat of Cyata, these vulnerabilities (CVE-2026-2275, CVE-2026-2286, CVE-2026-2287, CVE-2026-2285) are linked to the Code Interpreter tool, which allows users to execute Python code within a Docker container. Attackers can leverage prompt injection to exploit these bugs, escaping the sandbox environment and executing arbitrary code on the host machine. The vulnerabilities are due to improper default configurations and insufficient validation. Although patches are in development, mitigation involves restricting the Code Interpreter tool, disabling code execution flags, and sanitizing inputs.

## Attack Chain

1.  Attacker injects malicious prompts into a CrewAI agent that utilizes the Code Interpreter tool.
2.  CVE-2026-2275 is exploited, causing the Code Interpreter tool to fall back to SandboxPython when Docker is inaccessible, potentially enabling arbitrary C function calls.
3.  Successful exploitation of CVE-2026-2275 allows the attacker to trigger CVE-2026-2286, a server-side request forgery (SSRF) bug, by manipulating the RAG search tools with malicious URLs, potentially retrieving content from internal services.
4.  CVE-2026-2287 is exploited by bypassing Docker runtime checks and falling back to an insecure sandbox setting, enabling remote code execution.
5.  The attacker leverages CVE-2026-2285, an arbitrary local file read vulnerability in the JSON loader tool, to access sensitive files on the server by injecting malicious file paths.
6.  The attacker chains the exploits together to escape the Docker sandbox.
7.  Arbitrary code is executed on the host machine.
8.  The attacker steals credentials or achieves other objectives, such as persistent access or data exfiltration.

## Impact

Successful exploitation of these vulnerabilities allows attackers to escape the sandbox environment and execute code on the host machine or read files from its file system, potentially leading to credential theft, data breaches, and complete system compromise. While the specific number of victims is unknown, any system using CrewAI with the Code Interpreter tool is potentially at risk. Targeted sectors would include organizations leveraging AI and multi-agent systems for automation and task management.

## Recommendation

*   Restrict or remove the Code Interpreter tool to eliminate the primary attack vector as described in the overview.
*   Disable the code execution flag in agent configurations unless absolutely necessary, as highlighted in the overview.
*   Limit agent exposure to untrusted input and implement strict input sanitization to prevent prompt injection attacks as mentioned in the attack chain.
*   Prevent fallback to insecure sandbox modes to mitigate the risk associated with CVE-2026-2275 and CVE-2026-2287 as described in the attack chain.
*   Monitor for unexpected file access attempts that could indicate exploitation of CVE-2026-2285, using a file_event rule.
*   Implement network monitoring to detect and block potential SSRF attacks related to CVE-2026-2286 targeting internal or cloud services, using a network_connection rule.
