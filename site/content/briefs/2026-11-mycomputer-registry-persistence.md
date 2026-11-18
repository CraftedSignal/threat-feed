---
brief_id: brief-2026-11-18-mycomputer-registry-persistence
event_id: brief-2026-11-18-mycomputer-registry-persistence
revision: 1
activity_at: "2026-11-18T13:53:06Z"
title: Potential Persistence Via MyComputer Registry Keys
slug: 2026-11-mycomputer-registry-persistence
description: The 'MyComputer' registry key and its subkeys can be modified to execute arbitrary binaries when associated system actions are triggered, providing a potential mechanism for persistence.
date: "2026-11-18T13:53:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.persistence
affected_os:
  - windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_mycomputer.yml
  - https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/
rules:
  - title: Potential Persistence Via MyComputer Registry Keys
    description: Detects modification to the "Default" value of the "MyComputer" key and subkeys to point to a custom binary that will be launched whenever the associated action is executed.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview
Persistence can be established by modifying the 'Default' value of registry keys within the 'Microsoft\Windows\CurrentVersion\Explorer\MyComputer' registry hierarchy. By pointing these values to a custom binary, the system will launch the specified file whenever the associated action is executed.

## Attack Chain
An actor modifies a 'Default' value within the 'MyComputer' registry hierarchy. When the user or system triggers the corresponding action (e.g., backup, cleanup, or defrag), the modified path causes the custom binary to be executed.

## Impact
This technique allows for the execution of arbitrary binaries, facilitating persistence on the affected system.

## Recommendation
Monitor registry modifications to the 'MyComputer' key and its subkeys. Ensure that modifications to 'Default' values correspond to expected system paths and binaries. Investigate any instances where these keys are updated to point to non-standard locations.
