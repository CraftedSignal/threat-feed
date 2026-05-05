---
title: Windows Defender Real-Time Behavior Monitoring Disabled via Registry Modification
slug: 2024-01-disable-windows-behavior-monitoring
description: Attackers modify Windows Registry keys associated with Windows Defender to disable real-time behavior monitoring, a common tactic used by malware to evade detection and persist on compromised systems.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - endpoint
  - registry-modification
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
rules:
  - title: Detect Windows Defender Real-Time Protection Disable
    description: Detects modifications to the registry that disable Windows Defender's real-time protection features.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Modifying Windows Defender Registry Keys
    description: Detects processes modifying registry keys associated with disabling Windows Defender real-time protection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers often disable real-time behavior monitoring in Windows Defender to evade detection and maintain persistence on compromised systems. This involves modifying specific registry keys to turn off real-time protection features. Disabling these features allows malware such as Remote Access Trojans (RATs), bots, and Trojans to operate undetected. The targeted registry keys control various aspects of real-time protection, including behavior monitoring, on-access scanning, and script scanning. Successful disabling of these features can lead to privilege escalation, arbitrary code execution, and long-term persistence.

## Attack Chain

1.  The attacker gains initial access to the system, possibly through phishing or exploitation of a vulnerability.
2.  The attacker executes a script or binary with administrative privileges.
3.  The script or binary modifies the registry to disable Windows Defender's real-time behavior monitoring by setting specific registry values to "0x00000001".
4.  Specifically, the registry keys targeted include those under `SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\` and `SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\`.
5.  The attacker disables Behavior Monitoring by modifying `DisableBehaviorMonitoring`.
6.  The attacker disables On Access Protection by modifying `DisableOnAccessProtection`.
7.  The attacker disables Script Scanning by modifying `DisableScriptScanning`.
8.  With real-time protection disabled, the attacker can now execute malicious code, escalate privileges, and establish persistence without immediate detection.

## Impact

Successful disabling of Windows Defender's real-time behavior monitoring allows malware to operate undetected. This can lead to data exfiltration, ransomware deployment, or the establishment of a persistent foothold within the compromised environment. Organizations may experience significant data loss, financial damage, and reputational harm.

## Recommendation

*   Deploy the Sigma rule `Detect Windows Defender Real-Time Protection Disable` to your SIEM to identify registry modifications related to disabling Windows Defender's real-time protection features.
*   Enable Sysmon Event ID 13 (Registry Event) with appropriate filtering to capture registry modifications.
*   Investigate any alerts triggered by the Sigma rule `Detect Windows Defender Real-Time Protection Disable` promptly to determine the legitimacy of the registry modifications.
*   Monitor endpoints for unexpected or unauthorized registry modifications, particularly those affecting Windows Defender settings.
