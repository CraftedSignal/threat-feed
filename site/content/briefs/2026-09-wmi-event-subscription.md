---
title: Detection of WMI Event Subscription Persistence
slug: 2026-09-wmi-event-subscription
description: This brief outlines the detection of Windows Management Instrumentation (WMI) event subscriptions used by attackers for persistence and privilege escalation.
date: "2026-09-01T12:28:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
  - wmi
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Detects creation of WMI event subscription persistence method
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-19-wmievent-wmieventfilter-activity-detected
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-20-wmievent-wmieventconsumer-activity-detected
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-21-wmievent-wmieventconsumertofilter-activity-detected
rules:
  - title: Detect WMI Event Subscription Persistence
    description: Detects creation of WMI event subscription persistence method using Sysmon event IDs 19, 20, and 21.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.003
    data_sources:
      - wmi_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy WMI subscription detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit mapping to Sysmon Event IDs
  hunt_leads:
    - lead: Search for existing WMI event subscriptions created by non-system accounts
      technique_id: T1546.003
      data_needed:
        - Sysmon Event IDs 19, 20, 21
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: WMI event subscriptions are a common persistence technique
  mitigation_plan:
    - priority: medium_term
      action: Review all existing WMI event subscriptions for unauthorized or suspicious activity
      owner: IT Operations
      addresses: Persistence via WMI
      evidence: WMI can be used to achieve stealthy persistence
---

Windows Management Instrumentation (WMI) provides a powerful interface for system administration, but it is frequently abused by threat actors to achieve persistence and execute arbitrary code. By configuring WMI event subscriptions, attackers can trigger the execution of malicious scripts or binaries in response to specific system events, such as system startup, time intervals, or process termination. These subscriptions consist of three primary components: an Event Filter to define the trigger condition, an Event Consumer to specify the action to take, and a Filter-To-Consumer Binding to link the two. Monitoring for the creation of these components is a critical detection capability for identifying adversary activity that attempts to maintain long-term access to a compromised Windows host.

## Impact

Successful abuse of WMI event subscriptions enables attackers to maintain persistent access that survives system reboots and is often invisible to standard user-mode autostart monitoring tools. This technique facilitates privilege escalation, lateral movement, and the execution of further stages of an attack chain within a target environment.

## Recommendation

* Enable Sysmon logging for WMI activity to provide the necessary telemetry for detection.
* Deploy the provided Sigma rule to your SIEM to monitor for the registration of new WMI event filters, consumers, and bindings.
* Establish a baseline of legitimate WMI event subscriptions in the environment to tune out administrative activity and reduce false positives.
