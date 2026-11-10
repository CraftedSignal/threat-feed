---
brief_id: brief-2026-11-10-linux-env-shell
event_id: brief-2026-11-10-linux-env-shell
revision: 1
activity_at: "2026-11-10T16:12:48Z"
title: 'Linux: Shell Invocation via Env Command'
slug: 2026-11-linux-env-shell
description: The env command can be used to invoke a system shell, which may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands.
date: "2026-11-10T16:12:48Z"
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
  - attack.execution
  - attack.t1059.004
  - linux
references:
  - https://gtfobins.github.io/gtfobins/env/#shell
  - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_env_shell_invocation.yml
rules:
  - title: Shell Invocation via Env Command - Linux
    description: Detects the use of the env command to invoke a shell. This may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands.
    platform: sigma
    severity: high
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The env command, typically used to set or modify environment variables, can be used to invoke a shell. This technique is documented in GTFOBins as a method to spawn a shell.

## Recommendation
Deploy the provided Sigma rule to detect the use of the env command to invoke a shell. Monitor for legitimate system operations that may trigger this alert, such as Github operations (e.g., ghe-backup).
