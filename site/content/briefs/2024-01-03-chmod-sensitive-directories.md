---
title: Chmod Activity Targeting Sensitive Linux Directories
slug: 2024-01-03-chmod-sensitive-directories
description: Attackers may use chmod to modify file permissions within sensitive Linux directories such as /tmp/, /etc/, and /opt/ to maintain persistence, escalate privileges, or disrupt system operations.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - defense-evasion
  - privilege-escalation
  - persistence
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: Permissions Modification
references:
  - https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md
rules:
  - title: Chmod Targeting Sensitive Directories
    description: Detects chmod targeting files in sensitive directory paths on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1222.002
    data_sources:
      - process_creation
      - linux
  - title: Chmod to executable on /tmp directory
    description: Detects chmod to make files executable in /tmp.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1222.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Attackers may leverage the `chmod` command on Linux systems to modify file permissions in sensitive directories. This can be used to establish persistence by altering permissions of startup scripts or cron jobs, escalate privileges by modifying permissions of sensitive binaries or configuration files, or disrupt system operations by restricting access to critical system resources. The referenced SysJoker malware has been observed using similar techniques. Detecting anomalous `chmod` activity…
