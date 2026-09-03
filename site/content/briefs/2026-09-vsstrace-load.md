---
title: Detecting Unusual Image Loads of vsstrace.dll
slug: 2026-09-vsstrace-load
description: Detection of anomalous process loading of the Volume Shadow Copy service DLL vsstrace.dll which may indicate unauthorized attempts to interact with or disrupt shadow copy operations.
date: "2026-09-03T13:36:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - volume-shadow-copy
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: The detection of vsstrace.dll loads is associated with potential attempts to interfere with Volume Shadow Copies.
    confidence_band: med
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vsstrace_susp_load.yml
  - https://github.com/ORCx41/DeleteShadowCopies
rules:
  - title: Detect Suspicious Volume Shadow Copy vsstrace.dll Load
    description: Detects the image load of vsstrace.dll by uncommon executables that are not located in standard system or authorized application directories
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for processes loading vsstrace.dll from non-standard locations like C:\Users\Public or C:\ProgramData
      technique_id: T1490
      data_needed:
        - Sysmon Event ID 7
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source rule provides specific logic for filtering standard paths.
---

This detection focuses on the unusual loading of 'vsstrace.dll' by non-standard processes on Windows systems. While 'vsstrace.dll' is a legitimate component of the Volume Shadow Copy service, its loading by unexpected executables outside of system-trusted directories or known backup software can be indicative of post-exploitation activity. Attackers often attempt to interact with, enumerate, or delete shadow copies as part of an Impact phase, typically to hinder recovery efforts during ransomware operations. Defenders should monitor for processes that load this library from unauthorized paths, particularly those that do not align with established baseline behavior for system administration or backup software.

## Impact

Successful unauthorized interaction with Volume Shadow Copy components can facilitate the deletion or corruption of system backups, significantly hindering disaster recovery capabilities and increasing the impact of data-destructive attacks such as ransomware.

## Recommendation

Deploy the Sigma detection rule below to monitor for suspicious DLL loads and tune the filter list against your environment's known backup and administrative software inventory to reduce false positives.

- Enable Sysmon image load logging (Event ID 7) to collect the necessary telemetry.
- Establish a baseline of legitimate applications that load vsstrace.dll in your environment to replace the generic 'Program Files' filters.
