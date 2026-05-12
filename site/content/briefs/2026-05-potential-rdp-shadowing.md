---
title: Potential Remote Desktop Shadowing Activity
slug: 2026-05-potential-rdp-shadowing
description: This brief detects potential remote desktop shadowing activity by identifying modifications to the RDP Shadow registry or the execution of processes indicative of an active RDP shadowing session, which adversaries may abuse to spy on or control other users' RDP sessions.
date: "2026-05-12T17:46:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rdp
  - shadowing
  - lateral-movement
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Windows NT
  - Microsoft Defender XDR
  - Elastic Endgame
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://blog.bitsadmin.com/spying-on-users-using-rdp-shadowing
  - https://swarm.ptsecurity.com/remote-desktop-services-shadowing/
rules:
  - title: Detect RDP Shadow Registry Modification
    description: Detects modification of the RDP Shadow registry key to enable shadowing without user consent.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - registry_set
      - windows
  - title: Detect RDPSaUacHelper or RDPSaProxy Execution
    description: Detects the execution of RdpSaUacHelper.exe or RdpSaProxy.exe, which are indicative of active RDP shadowing sessions.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
  - title: Detect MSTSC with Shadow Argument
    description: Detects the execution of mstsc.exe with the /shadow argument, indicating a potential RDP shadowing attempt.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies the modification of the Remote Desktop Protocol (RDP) Shadow registry or the execution of processes indicative of an active RDP shadowing session. The rule aims to detect adversaries abusing the RDP Shadowing feature to monitor or control other users' active RDP sessions. The rule leverages data from various sources including endpoint logs, Windows event logs (Sysmon), Elastic Endgame, Microsoft Defender XDR, and SentinelOne Cloud Funnel. RDP Shadowing can be abused to gain unauthorized access to sensitive information or perform malicious actions on behalf of the user.

## Attack Chain

1.  An attacker gains initial access to a system via compromised credentials or other means.
2.  The attacker modifies the RDP Shadow registry key to enable shadowing without user consent (e.g., setting the `Shadow` value to `2` or `4`).
3.  The attacker uses `mstsc.exe` with the `/shadow` parameter to initiate a shadowing session of a target user's RDP session. The attacker may also use the `/control` or `/noConsentPrompt` to further stealth their activities.
4.  Alternatively, the attacker may execute `RdpSaUacHelper.exe` or `RdpSaProxy.exe` processes, typically launched by `svchost.exe`, on the target system to facilitate the shadowing connection.
5.  The system allows the attacker to view and potentially control the target user's session.
6.  The attacker monitors user activity, steals credentials, or performs other malicious actions within the compromised session.
7.  The attacker attempts to maintain persistence by ensuring that the modified registry settings remain in place.

## Impact

Successful RDP shadowing can lead to unauthorized access to sensitive data, credential theft, and the ability to perform malicious actions on behalf of the compromised user. This can result in financial loss, data breaches, and reputational damage. The number of victims and sectors targeted depends on the scope of the attacker's initial access and the value of the targeted user's session.

## Recommendation

*   Monitor registry modifications related to the RDP Shadow key and alert on unexpected changes using the Sigma rule `Detect RDPSaUacHelper or RDPSaProxy Execution`.
*   Detect the execution of `mstsc.exe` with the `/shadow` parameter to identify potential shadowing attempts using the Sigma rule `Detect RDP Shadow Registry Modification`.
*   Enable Sysmon registry event logging and process creation logging to capture the necessary data for the Sigma rules above.
*   Investigate any alerts related to RDP shadowing promptly to determine if the activity is legitimate or malicious.
*   Review and restrict RDP shadow permissions to limit who can shadow sessions.
