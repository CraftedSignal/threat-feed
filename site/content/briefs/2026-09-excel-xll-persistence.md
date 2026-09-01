---
title: Persistence via Excel Add-in Registry Modification
slug: 2026-09-excel-xll-persistence
description: Attackers achieve persistence by registering malicious XLL add-ins in the Windows registry, causing them to load automatically when Excel is launched.
date: "2026-09-01T12:13:32Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
    evidence: Detect potential persistence via the creation of an excel add-in (XLL) file to make it run automatically when Excel is started.
    confidence_band: high
rules:
  - title: Detect Persistence via Excel Add-in Registry
    description: Detects the creation of an Excel add-in (XLL) registry entry that forces the file to load automatically when Excel starts.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring for Excel options subkeys.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for existing registry keys containing /R and .xll in Office Options hives.
      technique_id: T1137.006
      data_needed:
        - Endpoint registry dumps
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this as a persistence technique.
---

Persistence mechanisms targeting Microsoft Office applications are a common vector for maintaining access to compromised endpoints. One such technique involves the use of XLL files, which are Excel add-ins based on the Excel XLL Software Development Kit. By modifying specific registry keys associated with Excel options, an attacker can configure the application to load a malicious XLL file whenever Excel starts. This technique effectively hides the malicious component within the context of a trusted office application and ensures it executes every time the user interacts with the suite. Defenders should monitor registry modifications targeting the Excel options path to identify unauthorized add-in configurations.

## Impact

Successful exploitation allows for persistent, background execution of arbitrary code within the user's security context whenever Excel is initialized. This enables attackers to maintain long-term access, exfiltrate data, or deploy secondary payloads while remaining difficult to detect via traditional process-based monitoring.

## Recommendation

Deploy the provided Sigma rule to monitor registry modifications within Excel options. Audit existing Excel add-ins for unknown or unsigned XLL files in registry keys and startup directories.

## Tags
- persistence
- windows
- office
