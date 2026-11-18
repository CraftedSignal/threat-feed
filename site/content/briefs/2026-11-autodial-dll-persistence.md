---
brief_id: brief-2026-11-18-autodial-dll-persistence
event_id: brief-2026-11-18-autodial-dll-persistence
revision: 1
activity_at: "2026-11-18T13:51:43Z"
title: Potential Persistence Via AutodialDLL
slug: 2026-11-autodial-dll-persistence
description: Adversaries can utilize the AutodialDLL registry key as a persistence mechanism to load custom DLLs via the ws2_32 library.
date: "2026-11-18T13:51:43Z"
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
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_autodial_dll.yml
  - https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/
  - https://persistence-info.github.io/Data/autodialdll.html
rules:
  - title: Potential Persistence Via AutodialDLL
    description: Detects change the the "AutodialDLL" key which could be used as a persistence method to load custom DLL via the "ws2_32" library
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
Adversaries can achieve persistence by modifying the "AutodialDLL" registry key to load a custom DLL via the "ws2_32" library.

## Impact
This technique allows for loading a custom DLL to maintain persistence.

## Recommendation
Monitor registry modifications to the "AutodialDLL" key, ensuring that modifications are evaluated against the known legitimate values (rasadhlp.dll).
