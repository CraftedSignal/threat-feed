---
title: Detection of Unauthorized System Restore Disablement via Registry
slug: 2026-10-disabling-systemrestore
description: Threat actors, including those deploying Remote Access Trojans such as NjRAT, modify Windows Registry keys to disable System Restore and hinder recovery efforts.
date: "2026-10-12T17:42:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - impact
  - registry-abuse
  - rat
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: The following analytic detects the modification of registry keys to disable System Restore on a machine.
    confidence_band: high
rules:
  - title: Detect System Restore Disablement via Registry Modification
    description: Detects unauthorized modification of registry keys used to disable System Restore functionality
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1490
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring rules for System Restore paths
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requirement for visibility into registry modifications
  hunt_leads:
    - lead: Search for historical registry modifications to SystemRestore keys
      technique_id: T1490
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This activity is significant because disabling System Restore can hinder recovery efforts.
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to HKLM\SOFTWARE\Microsoft\Windows NT\SystemRestore
      owner: IT Operations
      addresses: T1490
      evidence: Hardening registry access prevents unauthorized tampering
---

Adversaries often target the Windows System Restore feature to prevent system recovery and hinder incident response activities. By modifying specific registry keys to disable System Restore, threat actors ensure that defenders cannot easily roll back a compromised system to a clean state. This tactic is frequently observed in campaigns utilizing Remote Access Trojans (RATs), such as NjRAT, to maintain long-term persistence and cover tracks after initial infection. The behavior involves updating the DisableSR or DisableConfig values within the SystemRestore registry hive to 1. This modification is a critical indicator of defense evasion and potential system tampering, requiring immediate investigation when observed outside of authorized administrative changes.

## Attack Chain

1. Initial access is gained through methods such as phishing or exploit kits (e.g., weaponized attachments).
2. The malware executes, often masquerading as a legitimate process to bypass endpoint security controls.
3. The attacker gains administrative or elevated privileges required to modify sensitive registry keys.
4. The malware targets Windows Registry paths: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore` or `SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore`.
5. The attacker updates `DisableSR` or `DisableConfig` values to `0x00000001` to explicitly disable System Restore functionality.
6. The attacker may further modify additional security settings or install persistence mechanisms to sustain the foothold.
7. Final objective is achieved, such as data exfiltration, ransomware deployment, or long-term command-and-control communication.

## Impact

The primary impact of this activity is the permanent loss of system recovery points, forcing defenders to rely on full imaging or clean builds for remediation. Disabling System Restore is a persistent evasion tactic that creates significant operational friction for security teams responding to RAT infections. If the modification remains undetected, an attacker can maintain persistence across reboots, facilitating ongoing data theft or further malicious activity on the targeted host.

## Recommendation

* Deploy the provided Sigma rule to monitor for unauthorized modifications to System Restore registry keys using Sysmon Event ID 13.
* Establish a baseline for authorized administrative changes to System Restore settings to tune out legitimate maintenance activity.
* Audit endpoint configurations for registry-based hardening policies that prevent modification of System Restore registry hives.
* Investigate instances where `DisableSR` or `DisableConfig` are set to `1` by non-privileged or suspicious processes immediately.
