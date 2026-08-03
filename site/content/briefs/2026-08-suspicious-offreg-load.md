---
title: Detection of Suspicious Offline Registry Library Usage
slug: 2026-08-suspicious-offreg-load
description: Detection of unauthorized processes loading offreg.dll to perform direct registry hive modification, potentially bypassing standard Windows Registry auditing.
date: "2026-08-03T08:54:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - persistence
  - windows
  - telemetry-bypass
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Offreg.dll enables direct read/write access to offline registry hives without invoking the Windows Registry API, bypassing its associated audit logging and telemetry.
    confidence_band: high
rules:
  - title: Potentially Suspicious Image Load of Offreg.dll
    description: Detects loading of offreg.dll by processes outside of standard system, program files, or defender directories, which may indicate an attempt to bypass registry auditing.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - persistence
    techniques:
      - T1112
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify all instances of offreg.dll being loaded by unsigned processes or processes not associated with standard administrative toolchains.
      technique_id: T1112
      data_needed:
        - Endpoint image load logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Adversaries may abuse this to stealthily modify registry hives while evading detection mechanisms.
---

The Offline Registry Library (offreg.dll) is a component designed to provide low-level access to Windows registry hives without requiring an active registry API connection. While intended for legitimate administrative and diagnostic tasks, this library is susceptible to abuse by attackers attempting to modify system configurations, persistence mechanisms, or security settings while bypassing standard Windows Registry monitoring telemetry. By loading offreg.dll into a process, an adversary can manipulate registry hives directly on disk, effectively evading audit logs that trigger on standard RegOpenKeyEx or RegSetValueEx calls. Defenders should monitor for unexpected processes loading this DLL from non-system and non-standard application paths.

## Impact

Successful abuse of offreg.dll allows attackers to achieve stealthy persistence, disable security features, or modify system policies without generating traditional process-based registry modification alerts. This creates a significant blind spot for security operations teams relying strictly on standard registry event logging.

## Recommendation

Deploy the Sigma detection rule below to identify non-standard processes loading offreg.dll in your environment. Prioritize investigation of processes executing from user-writable directories or temporary folders. Validate alerts against known administrative and backup tooling to minimize noise.
