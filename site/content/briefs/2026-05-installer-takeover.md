---
title: Potential Privilege Escalation via InstallerFileTakeOver (CVE-2021-41379)
slug: 2026-05-installer-takeover
description: This rule detects potential exploitation of the InstallerTakeOver vulnerability (CVE-2021-41379), where successful exploitation allows an unprivileged user to escalate privileges to SYSTEM.
date: "2026-05-12T19:00:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1909:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_2004:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_20h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2004:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_20h2:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - cve-2021-41379
  - windows
vendors:
  - Microsoft
products:
  - Edge
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2021-41379
    cvss: 5.5
    epss: 0.01181
references:
  - https://github.com/klinix5/InstallerFileTakeOver
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_installertakeover.toml
rules:
  - title: Detect Potential InstallerFileTakeOver via Suspicious Service Execution
    description: Detects CVE-2021-41379 exploitation — detects suspicious execution of elevation_service.exe with unexpected original file name or code signature.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential InstallerFileTakeOver via Suspicious Child Process
    description: Detects CVE-2021-41379 exploitation — detects suspicious processes spawned by elevation_service.exe.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The rule identifies a potential privilege escalation attempt by exploiting the InstallerTakeOver vulnerability (CVE-2021-41379). This vulnerability, when successfully exploited, allows an unprivileged user to gain SYSTEM-level privileges on a Windows system. The detection focuses on identifying suspicious processes running with SYSTEM privileges that deviate from the expected behavior of the `elevation_service.exe`, particularly those not signed by Microsoft or spawning command interpreters. The rule aims to detect exploitation attempts rather than the vulnerability itself. This is important for defenders because successful exploitation leads to full system compromise.

## Attack Chain

1.  An unprivileged user gains initial access to the system.
2.  The user leverages the InstallerTakeOver vulnerability to manipulate the Windows Installer service.
3.  A malicious binary overwrites or replaces the legitimate `elevation_service.exe`.
4.  The compromised `elevation_service.exe` is executed with SYSTEM privileges.
5.  The modified `elevation_service.exe` spawns a command interpreter (cmd.exe, powershell.exe) or other malicious process.
6.  The spawned process inherits SYSTEM privileges.
7.  The attacker performs malicious actions using the elevated privileges.
8.  The attacker achieves persistence or performs lateral movement within the network.

## Impact

Successful exploitation of CVE-2021-41379 allows an unprivileged user to escalate privileges to SYSTEM, leading to a complete compromise of the affected system. This can enable attackers to install malware, steal sensitive data, create new user accounts with administrative rights, or use the compromised system as a pivot point for further attacks within the network. The scope of impact depends on the attacker's objectives and the compromised system's role within the organization.

## Recommendation

*   Deploy the Sigma rule "Detect Potential InstallerFileTakeOver via Suspicious Service Execution" to your SIEM to detect suspicious execution of `elevation_service.exe` with unexpected original file name or code signature.
*   Deploy the Sigma rule "Detect Potential InstallerFileTakeOver via Suspicious Child Process" to your SIEM to detect suspicious processes spawned by `elevation_service.exe`.
*   Review and harden Windows Installer permissions to prevent unauthorized modifications as referenced in CVE-2021-41379.
*   Monitor file events for modifications to `elevation_service.exe` to identify potential service overwrite attempts.
