---
title: Detection of WMI Token Impersonation via Process Access Monitoring
slug: 2026-09-wmi-token-impersonation
description: Adversaries leverage WMI token impersonation to gain elevated privileges, a behavior detectable by monitoring specific process access masks requested by wmiprvse.exe.
date: "2026-09-21T19:10:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - wmi
  - privilege-escalation
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The following analytic detects WMI token impersonation by identifying wmiprvse.exe requesting the query, VM, and duplicate-handle rights associated with WMI process access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The following analytic detects WMI token impersonation by identifying wmiprvse.exe requesting the query, VM, and duplicate-handle rights associated with WMI process access.
    confidence_band: high
rules:
  - title: Detect WMI Process Token Impersonation
    description: Detects WMI token impersonation by identifying wmiprvse.exe requesting query, VM, and duplicate-handle rights or full access to other processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege-escalation
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for WMI process access
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific access masks used for WMI token impersonation.
  hunt_leads:
    - lead: Identify all processes accessed by wmiprvse.exe with high-privilege access masks
      technique_id: T1047
      data_needed:
        - Sysmon Event ID 10
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source details specific access masks indicative of token manipulation.
---

This detection brief addresses the abuse of Windows Management Instrumentation (WMI) to perform token impersonation, a technique frequently observed in malware campaigns such as Qakbot and activities linked to the Water Gamayun threat group. Attackers utilize WMI for lateral movement, execution, and privilege escalation. By monitoring Sysmon EventCode 10 (Process Access), defenders can identify instances where `wmiprvse.exe` requests sensitive process access rights - specifically query, VM, and duplicate-handle operations. These rights allow the WMI provider process to interact with or manipulate target process tokens, potentially leading to unauthorized privilege escalation. Monitoring for these specific access masks provides a high-fidelity method to detect malicious WMI usage while filtering for legitimate administrative activities.

## Impact

Successful WMI token impersonation allows an attacker to execute code in the security context of another process, typically leading to persistent access, privilege escalation, and lateral movement within the compromised environment. These techniques are characteristic of sophisticated malware families and threat actors focused on long-term data exfiltration and organizational disruption.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious process access requests initiated by the WMI provider. Ensure Sysmon EventCode 10 is enabled and centralized in your SIEM. Tune the rule by baselining administrative scripts or automation tools that perform legitimate WMI auditing.
