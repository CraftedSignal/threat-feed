---
brief_id: brief-2026-11-18-exefile-association-abuse
event_id: brief-2026-11-18-exefile-association-abuse
revision: 1
activity_at: "2026-11-18T13:51:32Z"
title: 'Windows Registry: Misuse of exefile for File Association'
slug: 2026-11-exefile-association-abuse
description: Attackers can abuse the Windows Registry to associate new file extensions with the 'exefile' handler, a technique used to bypass security products.
date: "2026-11-18T13:51:32Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  likelihood: roughly even chance
tags:
  - defense-evasion
affected_os:
  - windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_file_association_exefile.yml
  - https://twitter.com/mrd0x/status/1461041276514623491
rules:
  - title: New File Association Using Exefile
    description: Detects the abuse of the exefile handler in new file association. Used for bypass of security products.
    platform: sigma
    severity: high
    tactics:
      - stealth
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview
Threat actors can manipulate the Windows Registry to map new file extensions to the 'exefile' class. By associating an extension with the 'exefile' handler via the Registry, this technique is used to bypass security products.

## Recommendation
- Monitor registry set events where 'exefile' is used as a handler for new file extensions under the 'Classes' hive.
