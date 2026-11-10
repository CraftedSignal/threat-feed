---
brief_id: brief-2026-11-10-sdbinst-shim-persistence
event_id: brief-2026-11-10-sdbinst-shim-persistence
revision: 1
activity_at: "2026-11-10T03:04:03Z"
title: Windows Sdbinst.exe Shim Database Installation with Non-Standard Extensions
slug: 2026-11-sdbinst-shim-persistence
description: Adversaries may use sdbinst.exe to install shim databases with uncommon file extensions to establish persistence or elevate privileges.
date: "2026-11-10T03:04:03Z"
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
  - privilege-escalation
  - windows
  - sdbinst
references:
  - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
  - https://web.archive.org/web/20240115015113/https://github.com/nasbench/Misc-Research/blob/8ee690e43a379cbce8c9d61107442c36bd9be3d3/Other/Undocumented-Flags-Sdbinst.md
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sdbinst_susp_extension.yml
rules:
  - title: Detect Uncommon Extension Shim Database Installation
    description: Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.011
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The Windows Shim Database Installer (sdbinst.exe) is a utility used to install custom shim databases. Adversaries may use this tool to establish persistence or elevate privileges by executing malicious content triggered by application shims. Detection logic identifies the execution of sdbinst.exe when used with files lacking the standard .sdb extension, which may indicate the installation of a suspicious shim database.
