---
brief_id: brief-2026-11-10-lsass-recon-findstr
event_id: brief-2026-11-10-lsass-recon-findstr
revision: 1
activity_at: "2026-11-10T02:50:09Z"
title: LSASS Process Reconnaissance Via Findstr.EXE
slug: 2026-11-lsass-recon-findstr
description: Detection of findstr or find commands that include the keyword lsass, which indicates reconnaissance activity for the LSASS process PID.
date: "2026-11-10T02:50:09Z"
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
  - attack.credential-access
  - attack.t1552.006
references:
  - https://blog.talosintelligence.com/recent-cyber-attack/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_findstr_lsass.yml
rules:
  - title: LSASS Process Reconnaissance Via Findstr.EXE
    description: Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID
    platform: sigma
    severity: high
    data_sources:
      - process_creation
      - windows
rules_count: 1
---
