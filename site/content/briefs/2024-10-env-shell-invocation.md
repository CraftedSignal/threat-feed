---
title: Linux Shell Invocation via Env Command
slug: 2024-10-env-shell-invocation
description: The 'env' command is used to invoke a shell on Linux systems, potentially bypassing restricted environments or escalating privileges to execute arbitrary commands.
date: "2024-10-26T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - execution
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://gtfobins.github.io/gtfobins/env/#shell
  - https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html
rules:
  - title: Shell Invocation via Env Command - Linux
    description: Detects the use of the env command to invoke a shell, potentially indicating an attempt to bypass restricted environments or escalate privileges.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Shell Invocation via Env Command - Linux - Alternative Path
    description: Detects the use of the env command to invoke a shell, potentially indicating an attempt to bypass restricted environments or escalate privileges. This rule covers alternative paths to the env binary.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The 'env' command in Linux is typically used to run a program in a modified environment without altering the existing environment variables. However, attackers can abuse this command to invoke a shell directly, potentially bypassing restricted environments. This is often a technique used for privilege escalation or executing arbitrary commands in situations where direct shell access is limited. This activity matters for defenders because it can indicate an attacker attempting to gain…
