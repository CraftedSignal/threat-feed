---
brief_id: brief-2026-11-03-sentinelone-registry-tampering
event_id: brief-2026-11-03-sentinelone-registry-tampering
revision: 1
activity_at: "2026-11-03T03:39:40Z"
title: 'SentinelOne: Context menu scan command registry modification'
slug: 2026-11-sentinelone-registry-tampering
description: Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne.
date: "2026-11-03T03:39:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - persistence
  - registry
  - windows
  - sentinelone
references:
  - https://mrd0x.com/sentinelone-persistence-via-menu-context/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml
rules:
  - title: Detect Potential SentinelOne Shell Context Menu Tampering
    description: Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

The SentinelOne context menu scan command can be tampered with by unauthorized processes. By modifying the Windows registry keys associated with the SentinelOne shell context menu, a process other than SentinelOne may alter the command executed when the scan action is triggered.

## Recommendation
- Monitor for unauthorized modifications to the SentinelOne context menu registry keys using the provided detection logic.
- Investigate any processes, other than authorized Sentinel Agent binaries, that write to the registry subkeys under '\shell\SentinelOneScan\command\'.
