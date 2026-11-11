---
brief_id: brief-2026-11-11-unusual-cmd-parent
event_id: brief-2026-11-11-unusual-cmd-parent
revision: 1
activity_at: "2026-11-11T11:39:33Z"
title: Unusual Parent Process For Cmd.EXE
slug: 2026-11-unusual-cmd-parent
description: Detection logic for identifying cmd.exe spawned by specific parent processes.
date: "2026-11-11T11:39:33Z"
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
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/windows/execution_command_shell_started_by_unusual_process.toml
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_cmd_unusual_parent.yml
rules:
  - title: Unusual Parent Process For Cmd.EXE
    description: Detects suspicious parent process for cmd.exe
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

This detection monitors for the execution of cmd.exe when launched by specific, unusual parent processes on Windows systems.
