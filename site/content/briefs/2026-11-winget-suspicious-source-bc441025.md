---
brief_id: brief-2026-11-10-winget-suspicious-source-bc441025
event_id: brief-2026-11-10-winget-suspicious-source-bc441025
revision: 1
activity_at: "2026-11-10T03:08:05Z"
title: 'Winget: Detecting Addition of Suspicious Package Sources'
slug: 2026-11-winget-suspicious-source-bc441025
description: Detection of potential usage of winget to add new potentially suspicious download sources via IP addresses.
date: "2026-11-10T03:08:05Z"
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
references:
  - https://learn.microsoft.com/en-us/windows/package-manager/winget/source
  - https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_winget_add_susp_custom_source.yml
rules:
  - title: Detect Suspicious Winget Source Addition
    description: Detects the addition of a new winget source pointing to a direct IP address.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The Windows Package Manager (winget) can be used to add new package sources. This detection identifies the addition of sources via direct IP addresses, which may be potentially suspicious. This activity is monitored by tracking process creation events for winget.exe with specific command-line arguments.
