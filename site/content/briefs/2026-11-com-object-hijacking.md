---
brief_id: brief-2026-11-10-com-object-hijacking
event_id: brief-2026-11-10-com-object-hijacking
revision: 1
activity_at: "2026-11-10T08:46:59Z"
title: COM Object Hijacking via Registry Modification
slug: 2026-11-com-object-hijacking
description: Adversaries modify default system CLSID registry keys to point to malicious DLLs or executables, enabling persistence and privilege escalation.
date: "2026-11-10T08:46:59Z"
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
  validation_status: Needs laboratory validation before production deployment.
tags:
  - persistence
  - privilege-escalation
  - registry
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.015
    technique_name: Component Object Model Hijacking
    evidence: Adversaries modify default system CLSID registry keys to point to malicious DLLs or executables.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.015
    technique_name: Component Object Model Hijacking
    evidence: Modifying the default value allows malicious payloads to execute whenever the hijacked object is loaded.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_com_hijacking_builtin.yml
rules:
  - title: Detect COM Object Hijacking via System CLSID Modification
    description: Detects modification of COM InprocServer32 or LocalServer32 registry keys that point to suspicious, non-standard file paths.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.015
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
    - action: Deploy the Sigma detection rule to monitor Registry Event ID 13.
      owner: Detection Engineering
      due: 48h
      evidence: Source rule documentation identifies this as a critical detection point.
  hunt_leads:
    - lead: Identify registry modifications in CLSID subkeys pointing to user-writable directories.
      technique_id: T1546.015
      data_needed:
        - Registry set telemetry (Event ID 13)
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source indicates suspicious paths include common user-writable folders.
  mitigation_plan:
    - priority: medium
      action: Implement application control policies to restrict execution from writable directories like AppData or Temp.
      owner: IT Operations
      addresses: T1546.015
      evidence: Preventing execution from these directories mitigates the impact of successful hijacking.
---

Adversaries abuse the Component Object Model (COM) by hijacking legitimate CLSID (Class Identifier) entries. By modifying the `(Default)` value of `InprocServer32` or `LocalServer32` registry keys for specific built-in system COM objects, attackers can execute arbitrary code when those objects are initialized by legitimate processes. This technique is frequently observed in malware campaigns to achieve stealthy persistence and privilege escalation.

## Impact

Successful hijacking allows for the execution of arbitrary code in the context of the host process, which may lead to privilege escalation or persistent access to the system.

## Recommendation

Deploy the provided Sigma rule to monitor registry modifications targeting `InprocServer32` and `LocalServer32` keys, specifically filtering for paths associated with non-system or temporary directories. Audit existing COM object registrations periodically to identify unauthorized changes.
