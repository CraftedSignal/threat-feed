---
title: Detection of WMI Permanent Event Subscriptions for Persistence
slug: 2026-10-wmi-permanent-subscriptions
description: This brief outlines the detection of potential persistence and privilege escalation via WMI permanent event subscriptions, which attackers use to trigger malicious payloads on system events.
date: "2026-10-05T18:01:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - wmi
  - windows
  - sysmon
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.003
    technique_name: 'Event Triggered Execution: WMI Event Subscription'
    evidence: Attackers often use WMI event consumers to execute malicious code automatically when specific system events occur, such as system startup or user logon.
    confidence_band: high
rules:
  - title: Detect WMI Permanent Event Subscription Modification
    description: Detects the creation, modification, or deletion of a WMI permanent event subscription using Sysmon Event ID 21.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for Event ID 21 activity.
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation for T1546.003 detection.
  hunt_leads:
    - lead: Identify all existing WMI permanent event subscriptions on critical servers.
      technique_id: T1546.003
      data_needed:
        - WMI Event Consumer and Filter details
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Detection identifies potential persistence; auditing existing subscriptions is a high-value hunt.
  mitigation_plan:
    - priority: medium
      action: Review and remove unauthorized or unknown WMI permanent event subscriptions.
      owner: IT Operations
      addresses: Persistence via WMI
      evidence: Standard security practice for minimizing persistence vectors.
---

Windows Management Instrumentation (WMI) is a powerful administrative feature that can be abused by adversaries to maintain persistence or elevate privileges. By creating permanent event subscriptions, attackers can configure the system to execute arbitrary commands, scripts, or binaries whenever a specific event occurs, such as a process start, a logon, or a system timer trigger. This technique allows malicious code to execute with SYSTEM-level privileges if the consumer is configured appropriately. 

Defenders can identify this activity by monitoring WMI event binding events. Sysmon Event ID 21 specifically logs the creation, modification, or deletion of WMI permanent event subscriptions. Because legitimate administrative tools and software installers may occasionally create WMI subscriptions, security teams must establish a baseline of known-good activity to effectively reduce false positives during investigation.

## Impact

Successful abuse of WMI permanent event subscriptions provides attackers with a stealthy, system-wide mechanism to execute payloads without requiring a persistent file on disk or a traditional service. This can lead to long-term unauthorized access, data exfiltration, or further system compromise across the target environment.

## Recommendation

Detection engineering teams should focus on identifying unauthorized WMI event bindings. 

* Enable Sysmon version 6.1 or later on all Windows endpoints.
* Configure Sysmon to capture Event ID 21 (WmiEventFilter activity, WmiEventConsumer activity, and WmiEventConsumerToFilter activity).
* Deploy the provided Sigma rule to your SIEM to monitor for any WMI subscription modifications and investigate the associated consumer and filter paths.
* Baseline common administrative activity to tune the detection logic and suppress known, legitimate software subscriptions.
