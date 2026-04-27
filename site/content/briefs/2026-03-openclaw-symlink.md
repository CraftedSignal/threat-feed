---
title: OpenClaw Symlink Traversal via IDENTITY.md appendFile in agents.create/update
slug: 2026-03-openclaw-symlink
description: OpenClaw is vulnerable to symlink traversal via IDENTITY.md appendFile in agents.create/update. An attacker who can place a symlink in the agent workspace can hijack the IDENTITY.md path to append attacker-controlled content to arbitrary files on the system leading to remote code execution, persistent code execution, unauthorized SSH access, or service disruption.
date: "2026-03-27T14:00:00Z"
severities:
  - high
tags:
  - openclaw
  - symlink-traversal
  - vulnerability
  - npm
  - rce
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Privilege Escalation
references:
  - https://github.com/advisories/GHSA-7xr2-q9vf-x4r5
rules:
  - title: Detect OpenClaw Symlink Traversal Attempt via fs.appendFile
    description: Detects attempts to exploit the OpenClaw symlink traversal vulnerability by monitoring for fs.appendFile calls to IDENTITY.md without symlink resolution within agent workspace directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1202
      - T1547
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Creation of Symlink to Sensitive File
    description: Detects the creation of a symbolic link inside an agent workspace directory pointing to a sensitive system file like /etc/crontab or ~/.ssh/authorized_keys.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `openclaw` npm package is vulnerable to a symlink traversal vulnerability (CVE-2026-32013) affecting versions 2026.2.22 and earlier. The vulnerability lies in the `agents.create` and `agents.update` handlers within the `src/gateway/server-methods/agents.ts` file. These handlers use `fs.appendFile` on the `IDENTITY.md` file without proper symlink containment checks. An attacker capable of placing a symlink within the agent workspace can redirect the `IDENTITY.md` path to point to arbitrary…
