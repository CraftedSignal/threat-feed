---
title: Detect Suspicious WMI Event Subscription Creation for Persistence
slug: 2024-01-wmi-event-subscription
description: This threat brief details the detection of malicious Windows Management Instrumentation (WMI) event subscriptions, a technique used by attackers for persistence and privilege escalation on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - wmi
  - windows
  - event-subscription
vendors:
  - Microsoft
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
  - https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96
rules:
  - title: Detect Suspicious WMI Event Subscription Creation
    description: Detects the creation of a WMI Event Subscription with a suspicious consumer type
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - process_creation
      - windows
  - title: Detect WMI Event Filter Creation via Sysmon Event 21
    description: Detects WMI Event Filter creation using Sysmon event code 21, indicating potential persistence attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers abuse Windows Management Instrumentation (WMI) event subscriptions to establish persistence on compromised systems. By creating WMI event subscriptions that trigger malicious actions based on system events, adversaries can ensure their code executes automatically. This technique is particularly effective because WMI is a legitimate system administration tool, making malicious activity harder to detect. This rule focuses on detecting suspicious WMI event consumers, specifically `CommandLineEventConsumer` and `ActiveScriptEventConsumer`. The detection leverages Sysmon event code 21 and endpoint API events related to `IWbemServices::PutInstance` calls. The timeframe for the rule is set to look back 9 minutes.

## Attack Chain

1.  Attacker gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker uses PowerShell or another scripting language to interact with the WMI service.
3.  The attacker creates a new WMI event filter to monitor for a specific system event.
4.  The attacker creates a WMI event consumer, such as `CommandLineEventConsumer` or `ActiveScriptEventConsumer`, to execute a malicious payload.
5.  The attacker links the event filter and consumer by creating a WMI event subscription.
6.  The malicious WMI event subscription persists across reboots.
7.  When the specified event occurs, the malicious consumer executes the attacker's payload.
8.  The attacker maintains persistent access and can perform further malicious activities, such as data exfiltration or lateral movement.

## Impact

Successful exploitation allows attackers to maintain persistent access to the compromised system, even after reboots or other system changes. This can lead to long-term data theft, system compromise, or the deployment of ransomware. While the number of victims is unknown, this technique can be used against a wide range of Windows systems.

## Recommendation

*   Enable Sysmon WMI event logging to capture event code 21, which is crucial for detecting WMI event subscription creation.
*   Deploy the Sigma rule "Detect Suspicious WMI Event Subscription Creation" to your SIEM to identify potentially malicious WMI activity.
*   Investigate any process associated with the `IWbemServices::PutInstance` API call, particularly those using `CommandLineEventConsumer` or `ActiveScriptEventConsumer`, as indicated in the Attack Chain section.
*   Monitor for processes or activities around the time of the event to identify potential lateral movement or further persistence mechanisms as outlined in the overview.
