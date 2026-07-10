---
title: Persistence via WMI Event Subscription
slug: 2024-01-wmi-persistence
description: Adversaries leverage Windows Management Instrumentation (WMI) to establish persistence by creating event subscriptions that trigger malicious code execution when specific events occur, often utilizing `wmic.exe` to create event consumers.
date: "2024-01-03T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - wmi
  - event-triggered-execution
  - windows
vendors:
  - Microsoft
products:
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
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/003/
rules:
  - title: Detect WMI Event Subscription Creation via WMIC
    description: Detects the creation of WMI event subscriptions using wmic.exe with suspicious arguments.
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
  - title: Detect WMIC process spawning with persistence keywords
    description: Detects wmic.exe being used to create an ActiveScriptEventConsumer or CommandLineEventConsumer, often used for persistence.
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

Attackers can abuse Windows Management Instrumentation (WMI), a powerful Windows management framework, to maintain persistent access to systems. This involves creating WMI event filters, providers, consumers, and bindings that execute code upon specific event triggers. This technique allows threat actors to subscribe to events and execute arbitrary code when those events transpire, ensuring a persistent foothold on the targeted system. The detection focuses on the use of `wmic.exe` with specific arguments used to set up malicious WMI event subscriptions, a common method for attackers seeking to establish persistence. This activity can be difficult to detect without specific monitoring rules, making it a valuable technique for attackers targeting a wide range of Windows environments.

## Attack Chain

1. Initial Access: The attacker gains initial access to the system through various methods (not specified in source).
2. Privilege Escalation: The attacker may attempt to elevate privileges to perform WMI tasks.
3. Discovery: The attacker uses reconnaissance commands to explore the WMI environment.
4. WMI Event Filter Creation: The attacker uses `wmic.exe` to create a WMI event filter that defines the event to monitor.
5. WMI Event Consumer Creation: The attacker uses `wmic.exe` to create an event consumer, such as `ActiveScriptEventConsumer` or `CommandLineEventConsumer`, which specifies the action to take when the event occurs. This action is often malicious code execution.
6. WMI Binding Creation: The attacker creates a binding between the event filter and the event consumer, linking the trigger to the action.
7. Persistence: The WMI event subscription ensures that the malicious code is executed whenever the defined event occurs, providing persistence.
8. Execution: When the defined event occurs, the configured consumer executes the malicious payload.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised systems. This can lead to data theft, system disruption, or further malicious activities within the network. Due to the nature of WMI, this persistence mechanism can be difficult to detect and remove, potentially granting long-term access to the attacker. This technique impacts all Windows systems where WMI is enabled.

## Recommendation

*   Monitor process execution for `wmic.exe` with arguments "create", "ActiveScriptEventConsumer", or "CommandLineEventConsumer" to detect potential WMI event subscription abuse, as highlighted in the rule description.
*   Implement the provided Sigma rule to detect suspicious usage of `wmic.exe` related to WMI event subscription for persistence.
*   Investigate parent processes of `wmic.exe` for unexpected or unauthorized activity.
*   Regularly review WMI event filters, consumers, and bindings for any unauthorized or suspicious entries using tools like `wevtutil` or PowerShell.
