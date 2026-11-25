---
brief_id: brief-2026-11-25-hidden-ntfs-directory
event_id: brief-2026-11-25-hidden-ntfs-directory
revision: 1
activity_at: "2026-11-25T16:24:05Z"
title: Windows NTFS Hidden Directory Creation via INDEX_ALLOCATION Stream
slug: 2026-11-hidden-ntfs-directory
description: Attackers can manipulate NTFS INDEX_ALLOCATION streams to create hidden directories that are inaccessible to standard tools like explorer.exe and powershell.exe, facilitating stealthy file storage.
date: "2026-11-25T16:24:05Z"
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
  - stealth
  - file-system-manipulation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    subtechnique_id: T1564.004
    subtechnique_name: NTFS File Attributes
    evidence: Detects the creation of hidden file/folder with the ::$index_allocation stream which can be used as a technique to prevent access to folder and files from tooling.
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_hidden_dir_index_allocation.yml
  - https://twitter.com/pfiatde/status/1681977680688738305
  - https://web.archive.org/web/20250603152157/https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
  - https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/
  - https://github.com/redcanaryco/atomic-red-team/blob/5c3b23002d2bbede3c07e7307165fc2a235a427d/atomics/T1564.004/T1564.004.md#atomic-test-5---create-hidden-directory-via-index_allocation
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3
rules:
  - title: Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream
    description: Detects the creation of hidden file/folder with the '::$index_allocation' stream which can be used to prevent access from tools such as 'explorer.exe' and 'powershell.exe'.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.004
    data_sources:
      - windows
      - file_event
rules_count: 1
---

## Overview

Windows file systems support an NTFS-specific technique where appending the '::$index_allocation' stream to a directory name creates a hidden container. This manipulation prevents common Windows administrative and browsing tools, such as Windows Explorer and PowerShell, from accessing, listing, or deleting the directory or its contents.

## Impact

This technique is used as a method to prevent access to folders and files from standard tooling, potentially concealing malicious artifacts from forensic or administrative visibility.

## Recommendation

- Deploy file system monitoring capable of detecting the creation of files or directories containing the '::$index_allocation' string.
- Note that while Sysmon and ETW may be unable to log the presence of such streams in the CommandLine, some EDR solutions may be able to detect this via alternate telemetry such as console command history.
