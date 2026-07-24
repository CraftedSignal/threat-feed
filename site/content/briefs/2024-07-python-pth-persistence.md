---
title: Python .pth File Creation for Persistence
slug: 2024-07-python-pth-persistence
description: Attackers can establish persistence on Linux systems by creating malicious .pth files in Python package directories, causing arbitrary code execution on interpreter startup.
date: "2024-07-03T12:00:00Z"
lastmod: "2026-07-24T07:03:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - python
  - linux
  - pth
  - file_creation
vendors:
  - Microsoft
  - Palo Alto Networks
products:
  - Copilot Studio
  - PAN-OS GlobalProtect (10.2.x < 10.2.9-h1)
  - PAN-OS GlobalProtect (11.0.x < 11.0.4-h1)
  - PAN-OS GlobalProtect (11.1.x < 11.1.2-h3)
  - PAN-OS GlobalProtect (12.0.x < 12.0.0-h1)
  - PAN-OS GlobalProtect (12.1.x < 12.1.0-h1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://dfir.ch/posts/publish_python_pth_extension/
  - https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/
  - https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
  - https://hackread.com/aembit-extends-iam-for-agentic-ai-to-microsoft-copilot-studio/
  - https://sploitus.com/exploit?id=F640E363-33EA-5879-AB31-C2F1B1B5A088&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=F640E363-33EA-5879-AB31-C2F1B1B5A088
  - type: domain
    value: vuln-panos.example.com
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: Detect Suspicious Python .pth File Creation
    description: Detects creation of .pth files in standard Python library directories, excluding known legitimate processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    data_sources:
      - file_event
      - linux
  - title: Detect Modification of Python Path
    description: Detects modification of Python paths via file operations which could indicate malicious manipulation
    platform: sigma
    severity: low
    tactics:
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-06-16T15:02:04Z"
    level: L2
    summary: added CVE-2024-3400
    sources:
      - hackread
  - at: "2026-07-24T07:03:25Z"
    level: L1
    summary: new IOCs
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=F640E363-33EA-5879-AB31-C2F1B1B5A088&utm_source=rss&utm_medium=rss
---

Attackers can exploit Python's .pth file mechanism to achieve persistence on Linux systems. These files, placed in standard Python library directories, automatically execute arbitrary Python code when the interpreter starts. This technique allows for stealthy and persistent execution, bypassing traditional startup scripts or scheduled tasks. The Elastic detection rule identifies unauthorized creation of .pth files, excluding legitimate package managers and known benign processes. Volexity reported on CVE-2024-3400 which exploited this persistence technique in April 2024. This is relevant for defenders as it highlights a method for attackers to maintain access and execute malicious code within compromised environments, even after system reboots or updates.

## Attack Chain

1. Initial Access: An attacker gains initial access to a Linux system through an exploit (e.g., CVE-2024-3400) or compromised credentials.
2. Privilege Escalation (Optional): The attacker may escalate privileges to gain write access to system-wide Python package directories like `/usr/lib/python*/site-packages/`.
3. Malicious .pth Creation: The attacker creates a .pth file (e.g., `evil.pth`) within a Python package directory.
4. Payload Injection: The .pth file contains a path to a malicious Python script or directly includes Python code to execute. This code may download and execute a secondary payload, establish a reverse shell, or perform other malicious actions.
5. Interpreter Startup: When Python interpreter starts, it automatically executes the code specified in the .pth file.
6. Persistent Execution: The malicious code executes every time Python interpreter is invoked, ensuring the attacker maintains persistent access to the system.
7. Defense Evasion: The attacker may obfuscate the code within the .pth file or the linked script to evade detection.
8. Goal: The attacker maintains persistent access to the compromised system for lateral movement, data exfiltration, or other malicious objectives.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised Linux systems. The impact ranges from data theft and system disruption to complete system compromise. While no specific victim count is available, this technique can affect any organization relying on Python applications. The stealthy nature of .pth file-based persistence makes it difficult to detect, potentially leading to prolonged periods of undetected malicious activity.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious .pth file creation events in Python package directories.
*   Enable Elastic Defend integration to collect file creation events necessary for the provided Sigma rule.
*   Review and customize the exclusion list in the Sigma rule to account for legitimate package managers and automation processes within your environment.
*   Monitor system logs for unusual Python interpreter activity following .pth file creation events.
*   Investigate any alerts generated by the Sigma rule to determine the legitimacy of the .pth file creation and the code it executes.
*   Implement file integrity monitoring (FIM) on Python package directories to detect unauthorized modifications.
