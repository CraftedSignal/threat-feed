---
title: Detection of ETW Disabling via Registry Modification
slug: 2026-10-disable-etw-registry
description: Attackers modify registry keys to disable Event Tracing for Windows (ETW), effectively blinding security telemetry and facilitating defense evasion.
date: "2026-10-12T17:41:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - registry
  - etw
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The analytic detects modifications to the registry that disable the Event Tracing for Windows (ETW) feature.
    confidence_band: high
rules:
  - title: Detect ETW Disabling via Registry Modification
    description: Detects the modification of the .NETFramework ETWEnabled registry key to 0, which disables ETW logging.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.001
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
    - action: Deploy registry monitoring rules for the specified ETWEnabled path.
      owner: Detection Engineering
      due: 24h
      evidence: Source analytic description.
  hunt_leads:
    - lead: Search for historical registry set events targeting ETWEnabled
      technique_id: T1562.001
      data_needed:
        - Sysmon Event ID 13
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry modification indicates deliberate evasion attempt.
---

Adversaries frequently target the Event Tracing for Windows (ETW) subsystem to evade detection, as many security products and telemetry collectors rely on ETW for visibility into system processes and API calls. By modifying the registry path "*\SOFTWARE\Microsoft\.NETFramework\ETWEnabled" and setting the value to "0x00000000", an attacker can disable ETW for .NET processes. This technique is often observed as a preparatory step by ransomware actors and advanced persistent threats to ensure their malicious payloads execute without generating alerts. Because this registry modification is a common indicator of defensive impairment, monitoring for these specific registry set events is a high-priority activity for detection engineering teams.

## Attack Chain

1. Attacker gains initial access to the target host (e.g., via spearphishing or exploit).
2. Attacker executes a payload requiring elevated privileges or registry access.
3. Attacker identifies the target registry path: HKLM or HKCU\SOFTWARE\Microsoft\.NETFramework\.
4. Attacker modifies the "ETWEnabled" registry value, setting it to 0.
5. The OS or specific runtime environments (like .NET) apply the new configuration.
6. ETW logging is effectively disabled for subsequent .NET process activity.
7. Attacker proceeds with malicious actions (e.g., credential dumping, lateral movement) undetected by ETW-reliant tools.

## Impact

Disabling ETW significantly impairs the efficacy of endpoint detection and response (EDR) solutions, potentially allowing attackers to execute arbitrary code, move laterally, and exfiltrate data while remaining invisible to security monitoring. This technique has been observed in various ransomware campaigns documented by security researchers and incident response teams.

## Recommendation

1. Deploy the Sigma rule provided below to your SIEM to monitor for registry modifications targeting the ETWEnabled value.
2. Configure Sysmon Event ID 13 to log registry value sets and ensure the specific path "*\SOFTWARE\Microsoft\.NETFramework\ETWEnabled" is monitored.
3. Investigate any processes or user accounts attempting to set this registry value to 0, as this is rarely performed by legitimate administrative tasks.
