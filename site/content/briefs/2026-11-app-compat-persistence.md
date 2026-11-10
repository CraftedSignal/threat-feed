---
brief_id: brief-2026-11-10-app-compat-persistence
event_id: brief-2026-11-10-app-compat-persistence
revision: 1
activity_at: "2026-11-10T03:09:20Z"
title: Potential Persistence via AppCompat RegisterAppRestart Layer
slug: 2026-11-app-compat-persistence
description: Attackers may abuse the REGISTERAPPRESTART compatibility shim to achieve persistence by forcing malicious applications to restart automatically upon system login.
date: "2026-11-10T03:09:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - persistence
  - privilege-escalation
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
    subtechnique_id: T1546.011
    subtechnique_name: Application Shimming
    evidence: The REGISTERAPPRESTART compatibility layer allows an application to register for restart using the RegisterApplicationRestart API, potentially serving as a persistence mechanism.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_app_cpmpat_layer_registerapprestart.yml
  - https://web.archive.org/web/20240115021338/https://github.com/nasbench/Misc-Research/blob/d114d6a5e0a437d3818e492ef9864367152543e7/Other/Persistence-Via-RegisterAppRestart-Shim.md
rules:
  - title: Detect Potential Persistence via AppCompat RegisterAppRestart Layer
    description: Detects the setting of the REGISTERAPPRESTART compatibility layer on an application, which can be abused for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.011
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to identify registry modifications targeting AppCompat layers.
      owner: Detection Engineering
      due: 48h
      evidence: Source defines the registry path and detail value for detection.
  mitigation_plan:
    - priority: medium_term
      action: Baseline legitimate applications using AppCompat layers and restrict write access to registry hives managing these keys.
      owner: IT Operations
      addresses: T1546.011
      evidence: AppCompat shims are a known administrative configuration feature.
---

The Windows Application Compatibility (AppCompat) framework allows the application of specific shims or compatibility layers to executables to resolve legacy compatibility issues. Research indicates that the 'REGISTERAPPRESTART' layer can be abused as a persistence mechanism. By modifying registry keys within 'AppCompatFlags\Layers', an attacker can force an arbitrary executable to register for restart via the 'RegisterApplicationRestart' API. This causes the target application to launch automatically when the system restarts or the user logs in.

## Impact

Successful abuse of this technique results in persistent, automatic execution of a chosen binary with the privileges of the user account associated with the registry modification.

## Recommendation

- Deploy the provided Sigma rule to monitor modifications to 'AppCompatFlags\Layers'.
- Baseline existing entries in 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' to identify authorized compatibility settings.
- Investigate registry modifications targeting non-standard or user-writable paths for unexpected application shims.
