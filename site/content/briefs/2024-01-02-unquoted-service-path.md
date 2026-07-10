---
title: Potential Exploitation of Unquoted Service Path Vulnerability
slug: 2024-01-02-unquoted-service-path
description: This rule detects potential exploitation of unquoted service paths on Windows systems, which can lead to privilege escalation by identifying suspicious processes starting from common unquoted paths, indicating a potential attempt to execute malicious code.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - unquoted-service-path
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://attack.mitre.org/techniques/T1574/
  - https://attack.mitre.org/techniques/T1574/009/
  - https://attack.mitre.org/tactics/TA0004/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_unquoted_service_path.toml
rules:
  - title: Unquoted Service Path Exploitation
    description: Detects potential exploitation of unquoted service paths by identifying processes executing from vulnerable directories.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.009
    data_sources:
      - process_creation
      - windows
  - title: Unquoted Service Path Exploitation - Program.exe
    description: Detects potential exploitation of unquoted service paths where a program.exe is being executed from the root
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.009
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies attempts to exploit unquoted service paths on Windows systems. When a service path lacks quotes, Windows may execute a malicious executable placed in a higher-level directory within the path of an unquoted service executable. This occurs because Windows will search for and execute executables along the path, potentially launching a malicious program before reaching the intended service executable. The rule focuses on detecting process executions from vulnerable paths, such as `C:\Program.exe`, `C:\Program Files (x86)\`, or `C:\Program Files\`. Successful exploitation allows an attacker to escalate privileges and execute arbitrary code with elevated permissions. This is a common privilege escalation technique, frequently used after gaining initial access to a system. The rule is based on the Elastic detection rule "Potential Exploitation of an Unquoted Service Path Vulnerability" (rule_id: 12de29d4-bbb0-4eef-b687-857e8a163870).

## Attack Chain

1.  The attacker gains initial access to the system through various means (e.g., phishing, exploiting a different vulnerability).
2.  The attacker identifies a service with an unquoted path, such as `C:\Program Files\Example Service\service.exe`.
3.  The attacker places a malicious executable named `Program.exe` in `C:\`.
4.  The system attempts to start the service, resolving the unquoted path.
5.  Due to the missing quotes, Windows incorrectly parses the path and executes `C:\Program.exe` instead of the intended service.
6.  The malicious `Program.exe` executes with the privileges of the service account, potentially SYSTEM.
7.  The attacker gains elevated privileges and can perform actions such as installing software, modifying data, or creating new accounts.
8.  The attacker establishes persistence or moves laterally within the network.

## Impact

A successful unquoted service path exploitation allows an attacker to escalate privileges to the level of the service account, often SYSTEM. This can lead to complete system compromise, allowing the attacker to install malware, steal sensitive data, or create new administrative accounts. The impact is significant, potentially affecting all systems with vulnerable services. This attack targets Windows systems, and the number of affected systems depends on the prevalence of services with unquoted paths within the targeted environment.

## Recommendation

*   Deploy the Sigma rule "Unquoted Service Path Exploitation" to your SIEM to detect suspicious processes (process.executable) starting from common unquoted paths.
*   Review service configurations on Windows systems to identify and correct any unquoted service paths (T1574.009).
*   Implement enhanced monitoring and logging for suspicious process activities on the network to detect future attempts promptly (T1574).
*   Use the MITRE ATT&CK references provided to understand the attacker's tactics (TA0004) and techniques in greater detail.
