---
title: Abuse of WMI Permanent Event Subscriptions for Persistence
slug: 2026-10-wmi-permanent-event-subscription
description: Adversaries leverage WMI permanent event subscriptions to achieve stealthy persistence and arbitrary code execution by binding system event filters to malicious consumers.
date: "2026-10-05T18:01:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - wmi
  - windows
  - monitoring
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Given WMI consumers are often leveraged by adversaries for both execution and persistence purposes.
    confidence_band: high
rules:
  - title: Detect WMI Permanent Event Subscription
    description: Detects permanent WMI event subscriptions containing CommandLineEventConsumer or ActiveScriptEventConsumer, which are commonly leveraged for persistence and execution.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Microsoft-Windows-WMI-Activity/Operational event logging on all endpoint assets.
      owner: IT Operations
      due: 48h
      evidence: Required log source for detecting WMI event binding.
  hunt_leads:
    - lead: Search historical logs for Event ID 5861 to identify existing permanent subscriptions.
      technique_id: T1546.003
      data_needed:
        - WMI-Activity Event Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Permanent subscriptions are often used for long-term persistence.
  mitigation_plan:
    - priority: medium_term
      action: Review and remove unauthorized permanent WMI event subscriptions.
      owner: IT Operations
      addresses: T1546.003
      evidence: Removal of persistent objects prevents future execution.
---

Windows Management Instrumentation (WMI) provides a powerful interface for system management that can be weaponized by threat actors to achieve persistence and facilitate lateral movement or defense evasion. By creating a permanent event subscription, an attacker can register an `__EventFilter` that monitors for specific system occurrences (such as system uptime, user logon, or process creation) and triggers a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` when the conditions are met. These consumers allow for the execution of arbitrary commands or scripts with SYSTEM privileges. Because these subscriptions are stored in the WMI repository (CIM repository), they are highly resilient, often surviving reboots and potentially avoiding detection by traditional file-based security tools. Defenders must monitor the `Microsoft-Windows-WMI-Activity/Operational` event log, specifically Event ID 5861, to identify unauthorized binding operations that link these persistent event filters to suspicious consumers.

## Attack Chain

1. Attacker gains initial access and elevates privileges to local administrator or SYSTEM level.
2. Attacker crafts a malicious `__EventFilter` specifying a trigger condition (e.g., system boot time).
3. Attacker crafts a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` containing the payload command or script path.
4. Attacker uses `wmic` or PowerShell `Get-WmiObject` / `Set-WmiInstance` to register the `__EventFilter` object in the `root/subscription` namespace.
5. Attacker registers the `__EventConsumer` object containing the malicious payload instructions.
6. Attacker creates an `__FilterToConsumerBinding` instance to link the filter and the consumer.
7. The WMI service monitors the system for the filter condition specified in the `__EventFilter`.
8. Once the condition is met, the WMI service automatically executes the malicious payload specified in the consumer.

## Impact

Successful abuse of WMI permanent event subscriptions provides attackers with a robust, difficult-to-detect persistence mechanism that operates outside of typical user-mode startup locations. This allows for automated payload execution, credential dumping, or additional malware deployment across a wide range of Windows environments, potentially leading to full system compromise and long-term undetected access.

## Recommendation

Prioritize the identification and investigation of permanent WMI event subscriptions through the following actions:

* Enable the `Microsoft-Windows-WMI-Activity/Operational` event log and monitor specifically for Event ID 5861 to capture binding operations.
* Implement the provided Sigma rules or equivalent logic in your SIEM to alert on the creation of `CommandLineEventConsumer` or `ActiveScriptEventConsumer` types.
* Establish a baseline of legitimate WMI subscriptions in your environment to facilitate the tuning of alerts and to reduce false positives from administrative or software-driven management tasks.
* Regularly audit the WMI repository for suspicious objects bound to event filters that are not associated with known system management processes.
