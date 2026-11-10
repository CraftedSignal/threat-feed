---
brief_id: brief-2026-11-10-lsass-clone
event_id: brief-2026-11-10-lsass-clone
revision: 1
activity_at: "2026-11-10T02:51:43Z"
title: Potential Credential Dumping via LSASS Process Cloning
slug: 2026-11-lsass-clone
description: Adversaries may perform credential dumping by spawning a clone of the Local Security Authority Subsystem Service (LSASS) process.
date: "2026-11-10T02:51:43Z"
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
  - credential-access
  - lsass
  - process-cloning
references:
  - https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
  - https://web.archive.org/web/20211128075033/https://twitter.com/Hexacorn/status/1420053502554951689
  - https://twitter.com/SBousseaden/status/1464566846594691073?s=20
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_lsass_process_clone.yml
rules:
  - title: Potential Credential Dumping Via LSASS Process Clone
    platform: sigma
    severity: critical
    tactics:
      - credential-access
    techniques:
      - T1003
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Detection of a suspicious LSASS process clone that could be a sign of credential dumping activity. This technique involves an instance of the lsass.exe process being spawned by another lsass.exe process.

## Recommendation

- Deploy the Sigma rule (ID: c8da0dfd-4ed0-4b68-962d-13c9c884384e) to detect process creation events where lsass.exe is the parent of another lsass.exe instance.
