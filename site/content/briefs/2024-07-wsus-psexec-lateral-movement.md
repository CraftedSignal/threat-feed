---
title: Potential WSUS Abuse for Lateral Movement via PsExec
slug: 2024-07-wsus-psexec-lateral-movement
description: This rule detects potential abuse of Windows Server Update Services (WSUS) for lateral movement by identifying suspicious processes, specifically PsExec, initiated by WSUS (wuauclt.exe).
date: "2024-07-19T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - windows
  - wsus
  - psexec
vendors:
  - Microsoft
products:
  - Windows Server Update Services
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1072
    technique_name: Software Deployment Tools
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/wsus-spoofing
  - https://attack.mitre.org/techniques/T1072/
  - https://attack.mitre.org/techniques/T1210/
rules:
  - title: Potential WSUS Abuse for Lateral Movement via PsExec
    description: Detects potential WSUS abuse for lateral movement by identifying PsExec executions initiated by wuauclt.exe.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1072
      - T1210
    data_sources:
      - process_creation
      - windows
  - title: WSUS Download Directory with Unexpected Executable
    description: Detects executables running from the WSUS download directory, which can indicate WSUS abuse.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1072
      - T1210
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a potential abuse of Windows Server Update Services (WSUS) to execute PsExec, enabling lateral movement within a network. WSUS is designed to execute only Microsoft-signed binaries, which limits the executables that can be used to tools published by Microsoft. Attackers may try to exploit this trusted relationship to run tools like PsExec to move laterally. This is achieved by spoofing the WSUS server and pushing malicious updates. This activity is relevant for defenders because successful exploitation can lead to widespread compromise of systems within the organization.

## Attack Chain

1.  The attacker compromises or spoofs a WSUS server.
2.  The attacker configures the WSUS server to distribute a malicious "update". This is not a real update, but rather a signed Microsoft binary (PsExec) packaged for distribution.
3.  The WSUS client (wuauclt.exe) on a target machine requests updates from the WSUS server.
4.  The WSUS server provides the malicious PsExec "update" to the client.
5.  The WSUS client downloads the "update" to a directory such as "C:\Windows\SoftwareDistribution\Download\Install\*".
6.  The WSUS client executes PsExec (psexec64.exe or psexec.c) to execute commands on other systems in the network.
7.  PsExec attempts to connect to remote hosts, authenticating with credentials available to the WSUS client.
8.  The attacker gains unauthorized access to other systems, allowing for lateral movement and further malicious activities.

## Impact

Successful exploitation enables lateral movement within the network, potentially leading to widespread compromise. Attackers can gain unauthorized access to sensitive data, install malware, or disrupt critical services. While the exact number of victims and sectors are unknown, any organization using WSUS is potentially vulnerable. If successful, an attacker can use the compromised machines to further move through the network.

## Recommendation

*   Deploy the Sigma rule "Potential WSUS Abuse for Lateral Movement via PsExec" to your SIEM and tune for your environment.
*   Monitor process creations where the parent process is wuauclt.exe and the process executable path contains "Windows\\SoftwareDistribution\\Download\\Install" to detect potential WSUS abuse.
*   Implement enhanced monitoring and logging for WSUS activities to detect and respond to similar threats more effectively in the future.
*   Review the alert details to confirm the presence of the suspicious process execution, specifically checking for the parent process name "wuauclt.exe" and the child process name "psexec64.exe" or original file name "psexec.c".
