---
title: Persistence via WMI Event Subscription
slug: 2024-01-wmi-persistence
description: Adversaries can leverage Windows Management Instrumentation (WMI) to establish persistence by creating event subscriptions that trigger malicious code execution when specific events occur, using tools like wmic.exe to create event consumers.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - windows
  - wmi
vendors:
  - Microsoft
  - Crowdstrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - Sysmon
  - Elastic Defend
  - Elastic Endpoint Security
  - CrowdStrike Falcon
  - SentinelOne Cloud Funnel
  - Windows Security Event Logs
  - winlogbeat
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1
rules:
  - title: Detect Suspicious WMIC Process
    description: Detects suspicious wmic.exe process executions with arguments indicative of WMI event subscription abuse.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1047
      - T1546.003
    data_sources:
      - process_creation
      - windows
  - title: Detect WMI Event Consumer Creation via Command Line
    description: Detects the creation of WMI event consumers using command-line tools, indicative of potential persistence mechanisms.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Windows Management Instrumentation (WMI) provides a powerful framework for managing Windows systems, but adversaries can abuse its capabilities to establish persistence. By creating WMI event subscriptions, attackers can execute arbitrary code in response to defined system events. This technique involves creating event filters, providers, consumers, and bindings that automatically run malicious code. This can be achieved through tools like `wmic.exe`, which allows the creation of event consumers such as `ActiveScriptEventConsumer` or `CommandLineEventConsumer`. Successful exploitation of WMI for persistence allows attackers to maintain unauthorized access to a compromised system, even after reboots or other system changes. This activity has been observed across various environments, highlighting the need for robust detection mechanisms to identify and prevent WMI-based persistence.

## Attack Chain

1. An attacker gains initial access to a Windows system through unspecified means.
2. The attacker uses `wmic.exe` to create a WMI event filter that defines a specific event to monitor.
3. A WMI event consumer, such as `ActiveScriptEventConsumer` or `CommandLineEventConsumer`, is created using `wmic.exe` specifying the malicious code or script to execute when the event occurs.
4. A WMI binding is established between the event filter and the event consumer using `wmic.exe`, linking the event to the action.
5. The malicious WMI event subscription is activated, monitoring for the defined event.
6. When the specified event occurs, the WMI service triggers the execution of the associated malicious code or script through the event consumer.
7. The attacker gains persistent access to the system, as the WMI event subscription will re-activate after reboots.
8. The attacker can then perform additional malicious activities, such as lateral movement or data exfiltration.

## Impact

Successful exploitation of WMI for persistence can allow an attacker to maintain long-term, unauthorized access to a compromised system. This can result in data theft, system compromise, and further malicious activities. While the exact number of victims is not specified in the source, the broad applicability of this technique means that many Windows systems are potentially at risk. If the attack succeeds, the attacker gains a foothold on the system that is difficult to detect and remove, which can lead to significant operational disruption and financial loss.

## Recommendation

*   Enable process creation logging and monitor for `wmic.exe` with command-line arguments related to creating event consumers, specifically `ActiveScriptEventConsumer` or `CommandLineEventConsumer`, to trigger the Sigma rule "Detect Suspicious WMIC Process".
*   Deploy the provided Sigma rule to your SIEM to detect suspicious WMI event subscription creation.
*   Review the investigation steps outlined in the provided documentation to triage and analyze potential WMI persistence attempts.
*   Monitor Windows Security Event Logs and Sysmon for events related to WMI activity for broader coverage.
