---
title: Lanman NullSessionPipe Registry Modification for Lateral Movement
slug: 2024-01-lanman-nullsessionpipe
description: Adversaries may modify the NullSessionPipe registry key to enable anonymous access to named pipes, facilitating lateral movement and defense evasion by allowing unauthorized access to network resources.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares
rules:
  - title: NullSessionPipe Registry Modification
    description: Detects modifications to the NullSessionPipes registry key, which can indicate lateral movement preparation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021.002
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying NullSessionPipes Registry
    description: Detects suspicious processes modifying the NullSessionPipes registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021.002
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers may modify the `NullSessionPipe` registry setting in Windows to specify which pipes can be accessed anonymously. This allows them to prepare for lateral movement by making the added pipe available to everyone without authentication. This technique is related to the broader concept of abusing null sessions to gain unauthorized access to network resources, and could allow for remote code execution or information disclosure. The modification of this registry setting could indicate malicious intent and potentially lead to unauthorized access to sensitive data or systems. This activity can be detected across multiple platforms including Windows endpoints, M365 Defender, and Crowdstrike.

## Attack Chain

1.  The adversary gains initial access to a system within the target network (e.g., via phishing or exploiting a vulnerability).
2.  The attacker elevates privileges on the compromised system to gain the necessary permissions to modify the registry.
3.  The attacker uses a tool like `reg.exe` or PowerShell to modify the `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes` registry key.
4.  The attacker adds a new named pipe to the `NullSessionPipes` value, or modifies an existing one.
5.  The attacker attempts to connect to the target system using the newly accessible named pipe without authentication.
6.  If successful, the attacker can use the named pipe to execute commands or transfer files to the target system.
7.  The attacker leverages the access gained through the named pipe to move laterally to other systems within the network.
8.  The final objective is to gain access to sensitive data or systems.

## Impact

Successful exploitation can allow an attacker to move laterally within a network without authentication, bypassing traditional security controls. This could lead to the compromise of sensitive data, disruption of services, or the deployment of ransomware. The number of victims depends on the scope of the attack and the number of systems that are accessible through the modified named pipes.

## Recommendation

*   Enable Sysmon registry event logging to detect registry modifications (reference: "Data Source: Sysmon" in tags).
*   Deploy the Sigma rule "NullSessionPipe Registry Modification" to your SIEM to detect suspicious modifications to the `NullSessionPipes` registry key (reference: rule).
*   Monitor for processes modifying the `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes` registry key (reference: Attack Chain, step 3).
*   Review and restrict anonymous access to named pipes and shares based on documented business needs (reference: references).
