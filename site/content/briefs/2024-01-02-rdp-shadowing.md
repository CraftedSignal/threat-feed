---
title: Potential Remote Desktop Shadowing Activity
slug: 2024-01-02-rdp-shadowing
description: This rule detects potential Remote Desktop Shadowing activity by identifying modifications to the RDP Shadow registry or the execution of processes indicative of an active RDP shadowing session that allows adversaries to spy on or control other user's RDP sessions.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - rdp-shadowing
  - windows
vendors:
  - Microsoft
products:
  - Windows
  - Remote Desktop Services
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1563
    technique_name: Remote Service Session Hijacking
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
references:
  - https://blog.bitsadmin.com/spying-on-users-using-rdp-shadowing
  - https://swarm.ptsecurity.com/remote-desktop-services-shadowing/
rules:
  - title: RDP Shadow Registry Modification
    description: Detects modifications to the RDP Shadow registry key, indicating potential unauthorized RDP shadowing activity.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1563.002
    data_sources:
      - registry_set
      - windows
  - title: RDP Shadow Process Execution
    description: Detects the execution of RdpSaUacHelper.exe or RdpSaProxy.exe by svchost.exe, which is indicative of RDP shadowing activity.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1563.002
    data_sources:
      - process_creation
      - windows
  - title: RDP Shadow MSTSC Execution
    description: Detects the execution of mstsc.exe with the /shadow argument, indicating an attempt to shadow an RDP session.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1563.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Remote Desktop Shadowing is a feature intended for legitimate administrative purposes, allowing administrators to view or control active RDP sessions for support and troubleshooting. However, adversaries can abuse this feature to monitor or hijack user sessions without consent, leading to unauthorized access and data compromise. This activity is detected by monitoring for modifications to the RDP Shadow registry settings and the execution of specific processes linked to shadowing, such as "RdpSaUacHelper.exe", "RdpSaProxy.exe", and "mstsc.exe" with the "/shadow:*" argument. The rule identifies suspicious modifications to RDP Shadow registry settings, specifically changes in "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow", and the execution of associated processes by "svchost.exe". This activity can originate from internal or external actors and has been observed in various attacks aimed at lateral movement and data theft. Defenders should prioritize detection and prevention of RDP shadowing to prevent unauthorized access and session hijacking.

## Attack Chain

1.  The attacker gains initial access to the target system through compromised credentials or other means.
2.  The attacker modifies the RDP Shadow registry key `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow` to enable shadowing. This may involve setting the value to "1", "2", "3", or "4".
3.  The attacker uses `svchost.exe` to launch `RdpSaUacHelper.exe` or `RdpSaProxy.exe` to initiate the shadowing session.
4.  Alternatively, the attacker directly executes `mstsc.exe` with the `/shadow:<session ID>` argument to target a specific RDP session.
5.  The compromised host connects to the target RDP session, allowing the attacker to view or control the user's session.
6.  The attacker monitors the user's activity, captures sensitive information, or performs malicious actions within the compromised session.
7.  The attacker may use the compromised session to move laterally to other systems on the network.

## Impact

Successful RDP shadowing allows an attacker to gain unauthorized access to sensitive information displayed on the user's screen. This can include credentials, financial data, or proprietary information. The attacker can also control the user's session, potentially leading to data theft, system compromise, or further lateral movement within the network. This can result in significant financial losses, reputational damage, and legal liabilities. The number of affected users depends on the scope of the attack and the number of RDP sessions targeted.

## Recommendation

*   Monitor registry modifications to `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow` using a registry monitoring tool and deploy the "RDP Shadow Registry Modification" Sigma rule.
*   Alert on the execution of `RdpSaUacHelper.exe` or `RdpSaProxy.exe` spawned by `svchost.exe` using the "RDP Shadow Process Execution" Sigma rule.
*   Monitor for the execution of `mstsc.exe` with the `/shadow` argument using the "RDP Shadow MSTSC Execution" Sigma rule.
*   Review and harden RDP access policies, including multi-factor authentication and limiting RDP access to only necessary users and systems.
*   Implement enhanced monitoring and logging for RDP activities across the network.
