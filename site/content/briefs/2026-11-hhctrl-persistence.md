---
brief_id: brief-2026-11-13-hhctrl-persistence
event_id: brief-2026-11-13-hhctrl-persistence
revision: 1
activity_at: "2026-11-13T06:51:46Z"
title: Windows Registry Persistence via hhctrl.ocx Hijacking
slug: 2026-11-hhctrl-persistence
description: Attackers may achieve persistence by modifying the InprocServer32 registry key for the hhctrl.ocx component to point to a custom binary.
date: "2026-11-13T06:51:46Z"
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
references:
  - https://persistence-info.github.io/Data/hhctrl.html
  - https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hhctrl_persistence.yml
rules:
  - title: Detect Registry Persistence via hhctrl.ocx Hijacking
    description: Detects when an attacker modifies the registry value of the hhctrl CLSID to point to a custom binary.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

Attackers can achieve persistence on Windows systems by modifying the default value of the registry key associated with the CLSID {52A2AAAE-085D-4187-97EA-8C30DB990436}, which corresponds to the HTML Help Control (hhctrl.ocx). By modifying the InprocServer32 registry entry to point to a custom binary, the attacker can influence system behavior.

## Impact

Modifying this registry value facilitates persistence by enabling the execution of a specified binary when the component is loaded.

## Recommendation

Monitor registry set events for modifications to the CLSID {52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32 where the value does not point to the expected system locations for hhctrl.ocx.
