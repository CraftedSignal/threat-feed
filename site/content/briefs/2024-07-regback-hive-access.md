---
title: Suspicious Registry Hive Access via RegBack
slug: 2024-07-regback-hive-access
description: This rule detects attempts to access registry backup hives (SAM, SECURITY, SYSTEM) via RegBack on Windows systems, which can contain or enable access to credential material.
date: "2024-07-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - regback
  - windows
vendors:
  - Elastic
  - Sophos
  - Microsoft
  - Trend Micro
  - Symantec
  - Bitdefender
  - N-able Technologies
  - Cylance
  - McAfee
  - Padvish
products:
  - Endpoint Defense
  - Windows Defender Advanced Threat Protection
  - Symantec Endpoint Protection
  - Endpoint Security
  - AVDefender
  - Optics
  - Padvish AV
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_regback_sam_security_hives.toml
rules:
  - title: Registry Hive Access via RegBack
    description: Detects processes accessing the SAM, SECURITY, or SYSTEM registry hives in the RegBack directory.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.002
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Accessing RegBack Hives
    description: Detects unusual processes accessing registry backup hives.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious attempts to access registry backup hives (SAM, SECURITY, and SYSTEM) located in the `RegBack` folder on Windows systems. These hives contain sensitive credential material, making them attractive targets for attackers seeking to compromise system security. The detection logic focuses on file access events, specifically successful file opens, while excluding known benign processes such as `taskhostw.exe` and various AV/EDR solutions (SophosScanCoordinator.exe, MsSense.exe, ccSvcHst.exe, etc.) to minimize false positives. The rule is designed to provide defenders with high-fidelity alerts when unauthorized access to these critical registry hives is detected. The scope includes any Windows system where endpoint file access logging is enabled.

## Attack Chain

1.  An attacker gains initial access to the system through various means.
2.  The attacker attempts to access the `SAM`, `SECURITY`, or `SYSTEM` registry hives located in the `C:\\Windows\\System32\\config\\RegBack\\` directory.
3.  The attacker leverages a tool or script to open one or more of these registry hives. This could involve using built-in Windows utilities, scripting languages, or custom-developed tools.
4.  If the attacker successfully opens the `SAM` and `SYSTEM` hives, they can extract user account credentials, including usernames, password hashes, and other sensitive information. The `SECURITY` hive is also useful.
5.  The attacker may stage the registry hive files by copying them to a different location on the system for further analysis or exfiltration.
6.  The attacker uses credential dumping tools (e.g., Mimikatz, secretsdump.py) or custom scripts to extract credentials from the staged registry hives.
7.  The attacker leverages the extracted credentials to escalate privileges, move laterally within the network, or access sensitive data.
8.  The final objective is typically to gain unauthorized access to critical systems, steal sensitive data, or establish long-term persistence within the compromised environment.

## Impact

Successful exploitation of this technique can lead to the compromise of user account credentials, enabling attackers to escalate privileges, move laterally within the network, and gain unauthorized access to sensitive data. The impact can range from data breaches and financial losses to reputational damage and disruption of critical business operations. The number of victims can vary depending on the scope of the attacker's activities and the security posture of the targeted organization. Sectors commonly targeted include finance, healthcare, government, and critical infrastructure.

## Recommendation

*   Enable file access monitoring for the `C:\\Windows\\System32\\config\\RegBack\\` directory to capture file open events.
*   Deploy the Sigma rule `Registry Hive Access via RegBack` to your SIEM and tune the exclusions based on your environment.
*   Monitor `process_creation` events for unusual processes accessing files in `C:\\Windows\\System32\\config\\RegBack\\`, using the rule `Suspicious Process Accessing RegBack Hives`.
*   Enable Sysmon process creation logging and file creation to activate the rules above.
