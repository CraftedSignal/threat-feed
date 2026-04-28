---
title: Barracuda RMM Privilege Escalation via Filesystem ACLs
slug: 2024-01-barracuda-privesc
description: Barracuda RMM versions prior to 2025.2.2 are vulnerable to local privilege escalation, allowing attackers to gain SYSTEM privileges by exploiting overly permissive filesystem ACLs on the C:\Windows\Automation directory.
date: "2026-04-15T21:17:04Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - privilege-escalation
  - rmm
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-22676
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22676
rules:
  - title: Detect File Modification in Barracuda Automation Directory
    description: Detects file modifications within the C:\Windows\Automation directory, indicative of potential privilege escalation attempts targeting Barracuda RMM.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Execution from Barracuda Automation Directory
    description: Detects process execution from the C:\Windows\Automation directory, which may indicate exploitation of the Barracuda RMM privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Barracuda RMM versions prior to 2025.2.2 contain a critical privilege escalation vulnerability (CVE-2026-22676). A local attacker can exploit overly permissive filesystem ACLs on the C:\\Windows\\Automation directory to achieve SYSTEM-level privileges. By modifying existing automation content or placing malicious, attacker-controlled files within this directory, the attacker can leverage the built-in automation functionality of Barracuda RMM. These files are then executed with NT AUTHORITY\SYSTEM privileges during routine automation cycles, leading to full system compromise. This vulnerability allows an attacker with limited local access to escalate their privileges to the highest level on the system, potentially leading to lateral movement, data exfiltration, or system disruption.

## Attack Chain

1.  The attacker gains initial local access to the target system.
2.  The attacker identifies the C:\\Windows\\Automation directory and confirms overly permissive ACLs.
3.  The attacker crafts a malicious executable or script designed to execute commands with elevated privileges.
4.  The attacker modifies an existing automation script within the C:\\Windows\\Automation directory to execute their malicious code. Alternatively, the attacker places their malicious file directly into the C:\\Windows\\Automation directory.
5.  Barracuda RMM's automation service executes the modified or newly added file during its regular automation cycle, running the attacker's code under the NT AUTHORITY\SYSTEM account.
6.  The attacker's code executes, granting them SYSTEM-level privileges.
7.  The attacker leverages SYSTEM privileges to install backdoors, create new administrative accounts, or perform other malicious actions.

## Impact

Successful exploitation of this vulnerability grants a local attacker complete control over the affected system. This can lead to sensitive data theft, installation of ransomware, or use of the compromised system as a staging point for further attacks within the network. The lack of authentication and the ability to directly execute commands as SYSTEM makes this a highly critical vulnerability. Given the nature of RMM software, successful exploitation on one endpoint could be leveraged to compromise numerous systems managed by the RMM.

## Recommendation

*   Upgrade Barracuda RMM to version 2025.2.2 or later to patch CVE-2026-22676.
*   Monitor file modifications within the C:\\Windows\\Automation directory using the provided Sigma rule to detect suspicious activity.
*   Implement strict access control policies on the C:\\Windows\\Automation directory, limiting write access to only authorized accounts.
*   Review existing automation scripts for any unauthorized modifications.
