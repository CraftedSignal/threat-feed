---
title: Suspicious RDP Client Image Load
slug: 2024-01-suspicious-rdp-client-imageload
description: The rule detects suspicious loading of the Remote Desktop Services ActiveX Client (mstscax.dll) from unusual locations, potentially indicating RDP lateral movement on Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - threat-detection
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3
  - https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language
rules:
  - title: Suspicious RDP Client Image Load
    description: Detects suspicious image loading of the Remote Desktop Services ActiveX Client (mstscax.dll) outside of typical system paths, which may indicate RDP lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - image_load
      - windows
  - title: Suspicious RDP Client Image Load from Network Path
    description: Detects suspicious image loading of mstscax.dll from a network share, which is highly unusual for legitimate RDP client activity.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This detection identifies suspicious instances of the Remote Desktop Services ActiveX Client (mstscax.dll) being loaded from unusual or unauthorized locations on Windows systems. Attackers may leverage RDP lateral movement techniques by loading this DLL in unauthorized contexts to gain access and control over other systems within the network. The rule focuses on detecting anomalous loading patterns of mstscax.dll outside typical system paths, which can be indicative of malicious lateral movement attempts. This detection is applicable to environments using Elastic Defend and Sysmon.

## Attack Chain

1.  An attacker compromises a system within the network.
2.  The attacker attempts to move laterally using RDP.
3.  To facilitate the RDP connection, the attacker executes a process that loads the mstscax.dll.
4.  The mstscax.dll is loaded from a location outside the standard system paths (e.g., not from C:\Windows\System32).
5.  The system logs the image load event, capturing the process and the location from which mstscax.dll was loaded.
6.  The detection rule identifies the unusual loading of mstscax.dll based on the configured criteria.
7.  The attacker establishes a remote desktop session to a target system.
8.  The attacker gains control over the target system, enabling further malicious activities.

## Impact

A successful attack can allow unauthorized access to sensitive systems and data, leading to potential data breaches, financial losses, and reputational damage. Lateral movement via RDP can allow attackers to expand their control within the network, compromising additional systems and escalating the impact of the attack. Early detection of suspicious mstscax.dll loading can prevent further propagation of the attack.

## Recommendation

*   Deploy the Sigma rule `Suspicious RDP Client Image Load` to your SIEM and tune the `process.executable` exclusions for your environment to reduce false positives.
*   Enable Sysmon Event ID 7 (Image Loaded) to capture the necessary data for the Sigma rule `Suspicious RDP Client Image Load` to function.
*   Review the process executable path in alerts to determine if `mstscax.dll` was loaded from an unusual or unauthorized location.
*   Investigate the network connections associated with the process to identify any suspicious remote connections or lateral movement attempts as described in the Overview.
*   Implement network segmentation to limit the ability of adversaries to move laterally within the network as described in the Overview.
