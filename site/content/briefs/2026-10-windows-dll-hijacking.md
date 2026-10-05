---
title: Detection of DLL Search Order Hijacking and Sideloading
slug: 2026-10-windows-dll-hijacking
description: This analytic identifies potential DLL sideloading or search order hijacking by monitoring for the loading of known abuse-prone DLLs from non-standard directory paths on Windows endpoints.
date: "2026-10-05T12:24:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - persistence
  - privilege-escalation
  - defense-evasion
  - lotl
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The following analytic detects when DLLs with known abuse history are loaded from an unusual location.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1574/002/
  - https://hijacklibs.net/api/
  - https://wietze.github.io/blog/hijacking-dlls-in-windows
rules:
  - title: Detect DLLs with Known Abuse History Loaded from Suspicious Locations
    description: Detects loading of DLLs known to be used in sideloading attacks when loaded from non-standard directory locations.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1574.001
      - T1574.002
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sysmon Event ID 7 monitoring to capture library loads.
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation for analytic implementation.
  hunt_leads:
    - lead: Search for DLL loads originating from user-writable directories (e.g., AppData, Temp, ProgramData).
      technique_id: T1574.002
      data_needed:
        - Sysmon Event ID 7
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic description of DLL sideloading.
---

This detection focuses on identifying the abuse of DLL loading mechanisms, a common technique for persistence, privilege escalation, and defense evasion. Attackers place malicious DLLs in directories where applications look for dependencies, causing the application to load the attacker-controlled code instead of the legitimate library. This brief leverages research from hijacklibs.net to track known vulnerable DLLs and flag instances where they are loaded from unexpected locations. Defenders should note that this analytic requires Sysmon Event ID 7 to monitor image loads and relies on a reference lookup to distinguish between malicious and legitimate library loading patterns.

## Impact

Successful exploitation allows attackers to gain persistence, elevate privileges within the context of a legitimate process, or bypass security controls by executing arbitrary code. This technique is frequently observed in post-exploitation scenarios, including those associated with previous SolarWinds exploitation events and broader Living Off the Land (LotL) campaigns.

## Recommendation

* Enable Sysmon Event ID 7 (Image Loaded) logging across all Windows endpoints to support this detection.
* Implement the suggested lookup-based detection logic to compare loaded library names and paths against a known list of abuse-prone DLLs.
* Tune the detection by adding process paths or specific library/application combinations that are known to be benign in your environment to the filter list.
* Monitor the output for processes loading common DLLs from non-standard directories such as user profiles, temp folders, or writable application subdirectories.
