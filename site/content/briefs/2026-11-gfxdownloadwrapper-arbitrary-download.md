---
brief_id: brief-2026-11-10-gfxdownloadwrapper-arbitrary-download
event_id: brief-2026-11-10-gfxdownloadwrapper-arbitrary-download
revision: 1
activity_at: "2026-11-10T02:50:23Z"
title: Arbitrary File Download Via GfxDownloadWrapper.EXE
slug: 2026-11-gfxdownloadwrapper-arbitrary-download
description: GfxDownloadWrapper.exe can be executed with a URL argument to download files.
date: "2026-11-10T02:50:23Z"
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
  - lolbas
  - windows
  - file-transfer
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/2056cb7662509dc998fc6ce79636aec4e6c0397f/yml/HonorableMentions/GfxDownloadWrapper.yml
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_gfxdownloadwrapper_arbitrary_file_download.yml
rules:
  - title: Detect Arbitrary File Download via GfxDownloadWrapper.exe
    description: Detects execution of GfxDownloadWrapper.exe with a URL argument, excluding known legitimate Intel update paths.
    platform: sigma
    severity: medium
    tactics:
      - command-and-control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

GfxDownloadWrapper.exe can be executed via the command line with a URL as an argument to download files. This behavior is tracked by the LOLBAS Project.

## Detection

Monitor process creation events for GfxDownloadWrapper.exe where the command line contains 'http://' or 'https://', excluding known legitimate traffic to 'https://gameplayapi.intel.com/'.
