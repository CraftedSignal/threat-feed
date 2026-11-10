---
brief_id: brief-2026-11-10-winget-suspicious-source
event_id: brief-2026-11-10-winget-suspicious-source
revision: 1
activity_at: "2026-11-10T02:45:07Z"
title: Potential Suspicious Winget Package Installation
slug: 2026-11-winget-suspicious-source
description: This detection identifies potential suspicious Winget package installations by monitoring for Zone.Identifier streams on files downloaded to the Winget temporary directory from specific sources.
date: "2026-11-10T02:45:07Z"
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
  - attack.stealth
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_stream_hash/create_stream_hash_winget_susp_package_source.yml
rules:
  - title: Detect Potential Suspicious Winget Package Installation
    platform: sigma
    severity: high
    tactics:
      - persistence
      - stealth
    data_sources:
      - create_stream_hash
      - windows
rules_count: 1
---

This detection identifies potential suspicious Winget package installations. It specifically monitors the creation of Zone.Identifier alternate data streams associated with files downloaded to the Winget temporary directory. The rule triggers when files are marked with a ZoneId of 3 and originate from specific URL patterns.

## Reference
- https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
