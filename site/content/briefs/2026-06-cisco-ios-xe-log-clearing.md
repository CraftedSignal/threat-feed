---
brief_id: brief-2026-06-cisco-ios-xe-log-clearing
event_id: brief-2026-06-cisco-ios-xe-log-clearing
revision: 1
activity_at: "2026-06-14T19:35:18Z"
title: Cisco IOS XE Log Clearing and Loopback Removal Sequence
slug: 2026-06-cisco-ios-xe-log-clearing
description: This brief details suspicious command sequences on Cisco IOS-XE devices, involving 'show logging', 'clear logging', and 'exit', potentially accompanied by 'no interface Loopback' commands, indicating defense evasion and potential network disruption by threat actors.
date: "2026-06-14T19:35:18Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2023-10-16T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*
  - cpe:2.3:o:rockwellautomation:allen-bradley_stratix_5200_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:rockwellautomation:allen-bradley_stratix_5800_firmware:*:*:*:*:*:*:*:*
tags:
  - defense-evasion
  - network-device
  - cisco
  - ios-xe
  - command-execution
  - state-sponsored
vendors:
  - Cisco
products:
  - Cisco IOS XE
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    subtechnique_id: T1070.001
    subtechnique_name: Clear Windows Event Logs
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
cves:
  - id: CVE-2023-20198
    cvss: 10
    epss: 0.94013
    kev: true
    kev_status: "true"
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
  - https://blog.talosintelligence.com/salt-typhoon-analysis/
rules:
  - title: Cisco IOS XE - Suspicious Log Clearing Command
    description: Detects the execution of 'clear logging' command on Cisco IOS XE devices, which is a common defense evasion technique used by attackers to remove forensic evidence. This rule should be correlated with other suspicious activities or user contexts for high-fidelity alerts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
      - T1070.001
    data_sources:
      - application
      - cisco_ios
  - title: Cisco IOS XE - Loopback Interface Removal Command
    description: Detects the execution of 'no interface Loopback' command on Cisco IOS XE devices, which can be an attempt by attackers to disrupt network services, impair defenses, or obscure C2 infrastructure.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1529
      - T1562
    data_sources:
      - application
      - cisco_ios
  - title: Cisco IOS XE - Suspicious Command Sequence Indicators
    description: 'Detects the presence of key commands typically found in an attacker''s defense evasion sequence on Cisco IOS XE devices: ''show logging'', ''clear logging'', and ''exit''. While a single event detection, it indicates the presence of these suspicious keywords.'
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
      - T1070.001
    data_sources:
      - application
      - cisco_ios
rules_count: 3
updates:
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2023-20198
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This threat brief focuses on detecting post-exploitation activity on Cisco IOS XE network devices, specifically the execution of a sequence of commands designed for defense evasion and potential network disruption. The observed patterns involve an attacker surveying device logs, clearing them to obscure their tracks, and potentially removing network interfaces like loopbacks. While the specific initial access vector is not detailed by these detection patterns, the activity is consistent with advanced persistent threat (APT) groups, such as those implicated in the CISA advisory AA25-239A, which links PRC state-sponsored actors to exploitation of network devices. These sequences are critical for defenders to identify as they indicate an attacker's attempt to maintain persistence or conduct further actions without detection, making incident response significantly more challenging.

## Attack Chain

1.  **Initial Access**: (Implicit) A threat actor gains unauthorized administrative access to a Cisco IOS XE network device, potentially through compromised credentials, exploitation of a known vulnerability (e.g., CVE-2023-20198), or other initial access methods.
2.  **Device Reconnaissance**: The attacker executes `show logging` commands to survey the device's current log configurations, review recent activity, and understand what information is being recorded.
3.  **Defense Evasion - Log Clearing**: The attacker then executes `clear logging` to erase critical security and operational logs from the device, thereby destroying forensic evidence of their presence and activities.
4.  **Defense Evasion - Network Obscuration/Disruption (Optional)**: In some observed sequences, the attacker might execute `no interface Loopback <interface_number>` to remove a loopback interface. This action can serve to disrupt network services, remove an interface used for monitoring, or further obscure their activities.
5.  **Session Termination**: The attacker concludes their interaction with the device by executing the `exit` command, terminating the administrative session.
6.  **Impact Prolongation**: Having cleared logs and potentially manipulated interfaces, the attacker proceeds with further malicious actions, such as establishing persistence, lateral movement, or data exfiltration, with reduced risk of immediate detection.

## Impact

The successful execution of these command sequences on Cisco IOS XE devices has severe consequences. The primary impact is a significant loss of forensic visibility, making it extremely difficult for security teams to understand the scope, timeline, and methods of the compromise. This lack of audit trails severely hampers incident response efforts, allowing attackers to remain undetected for longer periods and exfiltrate sensitive data or establish robust persistence. Furthermore, the removal of loopback interfaces can cause network instability, disrupt routing, and impact critical services, leading to operational downtime and economic losses. Such activities are often characteristic of state-sponsored actors targeting critical infrastructure or high-value organizations for espionage or disruptive purposes, as highlighted in CISA's advisories regarding PRC state-sponsored threats to network devices.

## Recommendation

*   Enable Cisco IOS-XE syslog with remote logging to a secure, external log management solution to ensure logs are retained even if local logs are cleared.
*   Ensure AAA command accounting is enabled on all Cisco IOS XE devices to log every command executed by administrative users.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious command executions.
*   Implement correlation rules in your SIEM to identify the execution of `show logging`, `clear logging`, `exit`, and `no interface Loopback` commands within a short timeframe (e.g., 2 minutes) originating from the same device and user.
*   Regularly review logs for `clear logging` and `no interface Loopback` events, investigating any occurrences outside of scheduled maintenance or authorized configuration changes.
