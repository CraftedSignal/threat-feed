---
title: RDP Enabled via Registry Modification
slug: 2024-01-rdp-registry-enabled
description: An adversary may enable Remote Desktop Protocol (RDP) access by modifying the `fDenyTSConnections` registry key, potentially indicating lateral movement preparation or defense evasion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - defense-evasion
  - rdp
  - registry-modification
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
affected_os:
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_rdp_enabled_registry.toml
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/001/
  - https://attack.mitre.org/techniques/T1112/
  - https://attack.mitre.org/tactics/TA0008/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: RDP Enabled via Registry Modification
    description: Detects registry modifications to enable Remote Desktop Protocol (RDP) access by setting fDenyTSConnections to 0.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021.001
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: RDP Enabled via Reg.exe
    description: Detects the use of reg.exe to modify the fDenyTSConnections registry key to enable RDP.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021.001
      - T1112
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may enable Remote Desktop Protocol (RDP) to facilitate lateral movement within a compromised network. By modifying the `fDenyTSConnections` registry key to a value of `0`, attackers can enable remote desktop connections, allowing them to access systems remotely. This technique can be employed using remote registry manipulation or tools like PsExec. The modification of the registry key is a common tactic used by ransomware operators and other threat actors to gain unauthorized access to victim servers. This activity can be performed to enable remote access for initial access or to regain access after persistence mechanisms have failed.

## Attack Chain

1. An attacker gains initial access to a system via an exploit or compromised credentials.
2. The attacker uses a tool like PsExec or leverages remote registry modification capabilities.
3. The attacker modifies the `fDenyTSConnections` registry key, setting its value to `0`. This key is typically located in `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`.
4. The system's RDP service is enabled or re-enabled as a result of the registry change.
5. The attacker attempts to connect to the now-enabled RDP service using valid or brute-forced credentials.
6. Upon successful authentication, the attacker gains interactive access to the system via RDP.
7. The attacker performs reconnaissance, elevates privileges, and moves laterally to other systems.
8. The attacker deploys ransomware, exfiltrates data, or achieves other objectives.

## Impact

Successful modification of the `fDenyTSConnections` registry key allows unauthorized remote access to systems, potentially leading to lateral movement, data theft, or ransomware deployment. Organizations could suffer significant financial losses, reputational damage, and operational disruption. The scope of the impact depends on the attacker's objectives and the level of access they gain within the environment.

## Recommendation

*   Deploy the Sigma rule "RDP Enabled via Registry" to detect modifications to the `fDenyTSConnections` registry key (rules).
*   Monitor process creation events for suspicious use of `reg.exe` or PowerShell to modify registry keys related to RDP (rules).
*   Implement network segmentation and firewall rules to restrict RDP traffic to authorized hosts (overview).
*   Review the privileges assigned to users and ensure the principle of least privilege is enforced (overview).
*   Enable Sysmon registry event logging to capture registry modifications (setup).
*   Investigate any alerts related to registry modifications on critical systems (overview).
