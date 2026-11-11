---
brief_id: brief-2026-11-11-linux-find-exec
event_id: brief-2026-11-11-linux-find-exec
revision: 1
activity_at: "2026-11-11T11:39:18Z"
title: 'Linux: Shell execution via find command'
slug: 2026-11-linux-find-exec
description: Detection of the use of the find command to execute a shell, which may be associated with privilege escalation, unauthorized command execution, or exploitation attempts.
date: "2026-11-11T11:39:18Z"
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
  - attack.discovery
  - attack.t1083
references:
  - https://gtfobins.github.io/gtfobins/find/#shell
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_find_shell_execution.yml
rules:
  - title: Shell Execution via Find - Linux
    platform: sigma
    severity: high
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The find command in Linux environments can be used to execute a shell. This behavior may be associated with privilege escalation, unauthorized command execution, or exploitation attempts. This detection focuses on process creation events where the find command is executed with the '-exec' flag in conjunction with common shell binaries.

## Detection Logic
The detection identifies the execution of the 'find' binary where the command line contains the '-exec' argument and references to common shells (/bin/bash, /bin/dash, /bin/fish, /bin/sh, or /bin/zsh).
