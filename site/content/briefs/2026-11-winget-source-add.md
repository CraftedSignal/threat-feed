---
brief_id: brief-2026-11-10-winget-source-add
event_id: brief-2026-11-10-winget-source-add
revision: 1
activity_at: "2026-11-10T04:38:24Z"
title: 'Winget: Addition of custom package sources'
slug: 2026-11-winget-source-add
description: This brief identifies the capability to monitor the Windows Package Manager (winget) for the addition of new download sources.
date: "2026-11-10T04:38:24Z"
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
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_winget_add_custom_source.yml
rules:
  - title: Detect Addition of New Winget Source
    description: Detects usage of winget to add new additional download sources.
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

The Windows Package Manager (`winget.exe`) supports the addition of new download sources via command-line arguments. This functionality can be monitored to track the registration of new package repositories.

## Detection
Monitoring should focus on process creation events for `winget.exe` where the command line contains arguments for adding a new source. Legitimate administrative use of this command may result in false positives.
