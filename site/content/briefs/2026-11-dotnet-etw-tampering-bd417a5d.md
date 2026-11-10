---
brief_id: brief-2026-11-10-dotnet-etw-tampering-bd417a5d
event_id: brief-2026-11-10-dotnet-etw-tampering-bd417a5d
revision: 1
activity_at: "2026-11-10T03:08:49Z"
title: 'Microsoft .NET Framework: ETW logging disablement via registry'
slug: 2026-11-dotnet-etw-tampering-bd417a5d
description: Adversaries may disable Event Tracing for Windows (ETW) for .NET processes by modifying specific registry keys to blind security monitoring tools.
date: "2026-11-10T03:08:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Rule tested against standard RegistrySet logic.
tags:
  - defense-impairment
  - persistence
  - windows
  - registry
  - .net
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries modifying registry keys to disable .NET ETW providers.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dot_net_etw_tamper.yml
rules:
  - title: Detect .NET ETW Logging Disablement
    description: Detects tampering with .NET ETW logging by setting ETWEnabled or COMPlus configuration keys to 0 in the registry.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1112
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
    - action: Deploy registry monitoring rules for .NET framework hives.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry keys used for ETW tampering.
  hunt_leads:
    - lead: Search for existing registry values set to 0 for ETWEnabled or COMPlus keys.
      technique_id: T1112
      data_needed:
        - Registry inventory/scans
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: These keys can be modified persistently to affect all .NET processes.
  mitigation_plan:
    - priority: medium
      action: Enforce GPOs to prevent unauthorized modifications to the .NETFramework registry hive.
      owner: IT Operations
      addresses: Registry tampering
      evidence: The technique relies on registry modification.
---

Adversaries can suppress ETW logging for .NET applications by setting registry values to zero. This technique interferes with the ability of security tools to record loaded .NET assemblies, effectively blinding EDR or SIEM telemetry that relies on these ETW providers. This involves modifying global configuration keys under the .NETFramework registry hive or setting environment-specific COMPlus variables via the registry.

## Impact

Successful exploitation prevents security products from gaining visibility into .NET assembly loading events, which are critical for detecting the execution of fileless malware, reflective DLL injection, and other memory-resident threats.

## Recommendation

Deploy detection rules to monitor for unauthorized modifications to the identified registry keys. Audit the environment for systems that have these keys set to zero.

## Attack Chain

1. Attacker gains administrative access to the target host.
2. Attacker modifies registry keys to alter .NET runtime behavior.
3. Attacker sets ETWEnabled or COMPlus_ETWEnabled/Flags to 0.
4. Subsequent .NET processes launched inherit these configurations.
5. Security telemetry (ETW) is suppressed for these processes.
6. Attacker proceeds with malicious actions (e.g., loading malicious assemblies) while bypassing detection.
