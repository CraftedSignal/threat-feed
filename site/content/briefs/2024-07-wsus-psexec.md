---
title: Potential WSUS Abuse for Lateral Movement via PsExec
slug: 2024-07-wsus-psexec
description: Adversaries may exploit Windows Server Update Services (WSUS) to execute PsExec for lateral movement within a network by abusing the trusted update mechanism to run signed binaries.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - wsus
  - psexec
  - windows
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
rules:
  - title: WSUS PsExec Execution
    description: Detects PsExec execution initiated by the Windows Update client (wuauclt.exe), indicating potential WSUS abuse for lateral movement.
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
  - title: WSUS Parent Process CommandLine Anomalies
    description: Detects unusual command lines for the wuauclt.exe process, potentially indicating WSUS abuse.
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

This detection identifies potential abuse of Windows Server Update Services (WSUS) for lateral movement by executing PsExec. WSUS is designed to manage updates for Microsoft products, ensuring only signed binaries are executed. Attackers can exploit this by using WSUS to distribute and execute Microsoft-signed tools like PsExec, which can then be used to move laterally within the network. This technique leverages the trust relationship inherent in WSUS to bypass security controls. The rule focuses on detecting suspicious processes initiated by `wuauclt.exe` (the Windows Update client) executing PsExec from the SoftwareDistribution Download Install directories. Defenders should monitor WSUS activity and PsExec executions to detect and respond to this potential threat.

## Attack Chain

1.  The attacker compromises a system within the target network.
2.  The attacker gains control over the WSUS server or performs a man-in-the-middle attack to spoof WSUS.
3.  The attacker uses the compromised WSUS server to approve a malicious update containing PsExec.
4.  The WSUS client (`wuauclt.exe`) on targeted machines downloads the "approved" update from the WSUS server, placing PsExec in the `C:\Windows\SoftwareDistribution\Download\Install\` directory.
5.  The WSUS client executes PsExec.
6.  PsExec is used to execute commands or transfer files to other systems on the network.
7.  The attacker uses the compromised systems to gather credentials or move laterally to other high-value targets.
8.  The attacker achieves their objective, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation allows attackers to achieve lateral movement within the network, leading to the compromise of additional systems and sensitive data. This can result in data breaches, financial loss, and reputational damage. The scope of impact depends on the level of access achieved by the attacker and the value of the compromised systems.

## Recommendation

*   Deploy the Sigma rule `WSUS PsExec Execution` to detect potential WSUS abuse involving PsExec execution.
*   Enable Sysmon process creation logging (Event ID 1) to gain visibility into process executions, as referenced in the [setup instructions](https://ela.st/sysmon-event-1-setup).
*   Implement enhanced monitoring and logging for WSUS activities to detect unauthorized changes or updates.
*   Investigate and remove any unauthorized binaries found in the `C:\Windows\SoftwareDistribution\Download\Install\` directory.
*   Review and restrict the accounts authorized to manage WSUS to prevent unauthorized modifications.
