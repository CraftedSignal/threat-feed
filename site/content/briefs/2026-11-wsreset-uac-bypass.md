---
brief_id: brief-2026-11-10-wsreset-uac-bypass
event_id: brief-2026-11-10-wsreset-uac-bypass
revision: 1
activity_at: "2026-11-10T03:07:39Z"
title: 'Windows: User Account Control bypass via WSReset.exe'
slug: 2026-11-wsreset-uac-bypass
description: Adversaries use the WSReset.exe binary to bypass User Account Control (UAC) and execute privileged processes.
date: "2026-11-10T03:07:39Z"
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
  - https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
  - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
  - https://web.archive.org/web/20240812143656/https://www.activecyber.us/activelabs/windows-uac-bypass
  - https://web.archive.org/web/20200530031302/https://twitter.com/ReaQta/status/1222548288731217921
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.yml
rules:
  - title: Detect UAC Bypass via WSReset.exe
    description: Detects use of WSReset.exe to bypass User Account Control (UAC). Adversaries use this technique to execute privileged processes.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

WSReset.exe is a Windows binary that can be abused to bypass User Account Control (UAC). Adversaries leverage this technique to execute processes with elevated privileges.

## Detection
The provided detection logic identifies suspicious activity by monitoring for child processes spawned by WSReset.exe, excluding the legitimate console host (conhost.exe).
