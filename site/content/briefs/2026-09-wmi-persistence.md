---
title: PowerShell WMI Event Subscription Persistence
slug: 2026-09-wmi-persistence
description: Adversaries utilize PowerShell to establish persistence and achieve privilege escalation by creating WMI event subscriptions that execute malicious payloads upon system triggers.
date: "2026-09-01T12:19:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - powershell
  - wmi
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.003
    technique_name: 'Event Triggered Execution: WMI Event Subscription'
    evidence: Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.003
    technique_name: 'Event Triggered Execution: WMI Event Subscription'
    evidence: Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmi_persistence.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.003/T1546.003.md
rules:
  - title: Detect PowerShell WMI Event Subscription Persistence
    description: Detects the creation of WMI event subscriptions (Filter or Consumer) via PowerShell New-CimInstance to establish persistence.
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 24h
      evidence: Required for detection of PowerShell-based WMI persistence
    - action: Deploy Sigma detection rule for WMI subscription creation
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 9e07f6e7-83aa-45c6-998e-0af26efd0a85
  mitigation_plan:
    - priority: medium_term
      action: Audit existing WMI subscriptions for unauthorized Event Filters and Consumers
      owner: SOC
      addresses: T1546.003
      evidence: Standard administrative maintenance
---

Adversaries frequently abuse Windows Management Instrumentation (WMI) to maintain persistence on compromised Windows hosts. By creating WMI event subscriptions, attackers can ensure their malicious code executes automatically when specific system conditions are met, such as system uptime, a specific time, or a user logon. This technique involves defining an Event Filter to monitor for a trigger and an Event Consumer to execute the payload. When using PowerShell to automate this process, adversaries often leverage the 'New-CimInstance' cmdlet to interact with the 'root/subscription' namespace. Because this mechanism relies on built-in administrative tools and runs with system privileges, it provides a stealthy way for attackers to maintain long-term access and potentially escalate privileges without needing to drop custom services or modify common startup locations.

## Attack Chain

1. Attacker gains initial code execution on a target Windows system.
2. Attacker prepares a malicious payload (e.g., a reverse shell or script).
3. Attacker uses PowerShell to define a WMI '__EventFilter' to monitor for a specific system trigger.
4. Attacker uses PowerShell to define a 'CommandLineEventConsumer' which specifies the command to execute.
5. Attacker links the filter and consumer using a '__FilterToConsumerBinding' instance.
6. The system reaches the trigger condition defined in the Event Filter.
7. The WMI service executes the Command Line Event Consumer with SYSTEM privileges.
8. Malicious code executes, achieving persistence or privilege escalation.

## Impact

Successful exploitation allows for long-term, stealthy persistence on a compromised host. Since WMI tasks often run as the SYSTEM account, this technique effectively facilitates privilege escalation if the initial access was obtained in a lower-privileged context. This enables attackers to survive reboots and evade simple detection methods that focus on common registry-based startup persistence.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture command-line activity.
- Deploy the provided Sigma rule to monitor for the creation of CIM instances related to WMI subscriptions.
- Audit existing WMI event consumers and filters for suspicious command-line arguments.
- Restrict access to administrative WMI namespaces for non-privileged accounts.
