---
title: LSASS Process Access via Windows API
slug: 2024-01-lsass-process-access
description: Detection of access attempts to the LSASS handle, indicating potential credential dumping by monitoring API calls (OpenProcess, OpenThread, ReadProcessMemory) targeting lsass.exe.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lsass
  - windows
vendors:
  - Microsoft
  - Elastic
products:
  - Microsoft Defender XDR
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
rules:
  - title: LSASS API Access by Non-Standard Process
    description: Detects access to LSASS process via OpenProcess or OpenThread API calls from processes outside standard program directories.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: LSASS ReadProcessMemory by Non-Standard Process
    description: Detects ReadProcessMemory calls targeting LSASS process from unusual locations.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule identifies attempts to access the LSASS process via Windows API calls, specifically `OpenProcess`, `OpenThread`, and `ReadProcessMemory`. The Local Security Authority Subsystem Service (LSASS) is a critical Windows component responsible for managing user authentication and security policies. Attackers often target LSASS to dump credentials from memory for lateral movement and privilege escalation. This detection focuses on identifying unusual processes attempting to access the LSASS process, excluding common legitimate applications and directories. The rule leverages data from Elastic Defend and Microsoft Defender XDR to identify suspicious activity and provide defenders with actionable alerts.

## Attack Chain

1. An attacker gains initial access to the target system through various means.
2. The attacker attempts to escalate privileges to gain administrative rights.
3. The attacker uses a custom tool or script to call the `OpenProcess`, `OpenThread` or `ReadProcessMemory` Windows APIs.
4. The tool targets the `lsass.exe` process to obtain a handle for memory access.
5. The attacker uses the obtained handle to read LSASS memory, searching for credential data.
6. The attacker extracts usernames, passwords, and other sensitive information from the dumped memory.
7. The attacker uses the stolen credentials for lateral movement to other systems on the network.
8. The attacker achieves their final objective, which may include data exfiltration or system compromise.

## Impact

Successful exploitation can lead to the compromise of domain credentials, allowing attackers to move laterally within the network and gain access to sensitive resources. This can result in data breaches, system compromise, and significant financial or reputational damage. The rule aims to detect these attacks early, limiting the scope of the potential compromise.

## Recommendation

*   Deploy the Sigma rule "LSASS API Access by Non-Standard Process" to your SIEM and tune for your environment to detect suspicious access to the LSASS process.
*   Investigate any alerts triggered by this rule, focusing on the process execution chain and the access rights requested as documented in the provided Microsoft documentation.
*   Enable process creation and API call logging via Elastic Defend or Microsoft Defender XDR to provide the necessary data for this detection.
*   Review and harden LSASS protection mechanisms such as Credential Guard to minimize the risk of successful credential dumping.
*   Implement the Osquery queries to gather system information like DNS cache, services, and unsigned executables, to aid in investigation and threat hunting.
