---
title: MEmu Android Emulator 9.2.7.0 Local Privilege Escalation
slug: 2026-07-memu-lpe
description: A local privilege escalation vulnerability (CVE-2026-36213) in MEmu Android Emulator 9.2.7.0 allows a low-privileged user to replace the 'MemuService.exe' binary due to insecure NTFS permissions, leading to arbitrary code execution with NT AUTHORITY\SYSTEM privileges upon service restart.
date: "2026-07-06T13:33:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - emulator
  - lpe
vendors:
  - Microvirt
products:
  - MEmu Android Emulator 9.2.7.0
affected_os:
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: 'The service binary located at C:\Program Files\Microvirt\MEmu\MemuService.exe is installed with insecure NTFS permissions, granting FullControl (F) to low-privileged groups: - BUILTIN\Users - Everyone. A low-privileged local user can replace the service binary with a malicious executable. Upon service restart, the malicious binary executes with NT AUTHORITY\SYSTEM privileges.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Example: Add new admin user os.system("net user hacked Password123! /add") os.system("net localgroup administrators hacked /add")'
    confidence_band: high
cves:
  - id: CVE-2026-36213
    cvss: 7.8
    epss: 0.00176
references:
  - https://www.exploit-db.com/exploits/52615
  - https://www.cve.org/CVERecord?id=CVE-2026-36213
  - https://cwe.mitre.org/data/definitions/732.html
  - https://github.com/sec-zone/Hijack-service-binaries
iocs:
  - type: domain
    value: memuplay.com
  - type: url
    value: https://www.memuplay.com/download.html
  - type: file_path
    value: C:\Program Files\Microvirt\MEmu\MemuService.exe
  - type: url
    value: https://github.com/sec-zone/Hijack-service-binaries
ioc_counts:
  domain: 1
  file_path: 1
  url: 2
rules:
  - title: Detects CVE-2026-36213 Exploitation — MEmuSVC Service Control
    description: Detects CVE-2026-36213 exploitation — attempts to stop and start the 'MEmuSVC' service using 'sc.exe' which may indicate an attempt to trigger a malicious service binary.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.003
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-36213 Exploitation — MEmuService.exe Binary Modification
    description: Detects CVE-2026-36213 exploitation — unauthorized modification of the 'MemuService.exe' binary, indicating an attempt to replace the legitimate service executable with a malicious payload.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A critical local privilege escalation (LPE) vulnerability, tracked as CVE-2026-36213, has been identified and publicly disclosed in MEmu Android Emulator version 9.2.7.0. The flaw stems from insecure NTFS permissions applied to the `MemuService.exe` binary, located at `C:\Program Files\Microvirt\MEmu\MemuService.exe`. This Windows service, named "MEmuSVC", operates with `NT AUTHORITY\SYSTEM` privileges. Due to FullControl permissions granted to low-privileged groups such as `BUILTIN\Users` and `Everyone` on the service binary, any local user can replace it with a malicious executable. Once replaced, restarting the "MEmuSVC" service will trigger the execution of the attacker's code with SYSTEM-level privileges, enabling full system compromise. The availability of a public exploit on Exploit-DB ([EDB-52615](https://www.exploit-db.com/exploits/52615)) significantly increases the urgency for remediation for all users of the affected software.

## Attack Chain

1.  **Initial Access**: A low-privileged attacker gains local access to a Windows system running MEmu Android Emulator 9.2.7.0.
2.  **Vulnerability Identification**: The attacker identifies the `MEmuSVC` service running with `NT AUTHORITY\SYSTEM` privileges and its associated binary `C:\Program Files\Microvirt\MEmu\MemuService.exe`.
3.  **Permission Check**: The attacker verifies the insecure NTFS permissions on `MemuService.exe` (e.g., using `icacls`), confirming that `BUILTIN\Users` or `Everyone` have FullControl access.
4.  **Payload Creation**: The attacker crafts a malicious executable (e.g., `payload.exe`) designed to perform actions like creating a new administrative user or establishing persistence.
5.  **Binary Replacement**: The attacker exploits the insecure permissions to replace the legitimate `C:\Program Files\Microvirt\MEmu\MemuService.exe` with their `payload.exe`.
6.  **Service Control**: The attacker stops the `MEmuSVC` service using `sc stop MEmuSVC`.
7.  **Privilege Escalation**: The attacker starts the `MEmuSVC` service using `sc start MEmuSVC`, which executes the malicious `payload.exe` with `NT AUTHORITY\SYSTEM` privileges.
8.  **Impact**: The malicious payload successfully executes, granting the attacker SYSTEM-level control over the compromised system.

## Impact

Successful exploitation of CVE-2026-36213 allows a local attacker to escalate privileges to `NT AUTHORITY\SYSTEM`, granting complete control over the compromised Windows system. This level of access enables attackers to install malware, modify system configurations, access sensitive data, create new administrative accounts, and potentially move laterally within the network. While the source does not specify victim counts or targeted sectors, any organization or individual using the vulnerable MEmu Android Emulator is at risk of full system compromise if an attacker gains initial local access.

## Recommendation

*   **Patch Immediately**: Update MEmu Android Emulator to a patched version that addresses CVE-2026-36213 as soon as one is available from Microvirt.
*   **File Integrity Monitoring**: Deploy file integrity monitoring (FIM) on `C:\Program Files\Microvirt\MEmu\MemuService.exe` to detect unauthorized modifications.
*   **Endpoint Detection**: Deploy the Sigma rules provided in this brief to your SIEM/EDR to detect attempts to replace the service binary or manipulate the `MEmuSVC` service.
*   **Sysmon Logging**: Enable Sysmon process creation (Event ID 1) and file creation/modification (Event ID 11) logging to activate the detection rules.
