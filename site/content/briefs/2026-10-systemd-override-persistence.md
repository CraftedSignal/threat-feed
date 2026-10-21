---
brief_id: brief-2026-10-21-systemd-override-persistence
event_id: brief-2026-10-21-systemd-override-persistence
revision: 1
activity_at: "2026-10-21T13:59:14Z"
title: Linux Systemd Service Override Configuration Persistence
slug: 2026-10-systemd-override-persistence
description: Systemd override configuration files can be leveraged by malicious actors to achieve persistence or escalate privileges by executing malicious commands during system startup or via systemd timers.
date: "2026-10-21T13:59:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    subtechnique_id: T1543.002
    subtechnique_name: Systemd Service
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    subtechnique_id: T1543.002
    subtechnique_name: Systemd Service
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_systemd_override_conf_creation.toml
---

Systemd override configuration files allow administrators to modify default service behavior. Attackers may create or rename these files in system or user service directories to inject directives such as `ExecStart`, `ExecStartPre`, `ExecStartPost`, `Environment`, or `OnCalendar`. This allows for the execution of unauthorized commands or payloads while leaving the original base unit file intact, facilitating persistent access and potential privilege escalation.

## Detection and Investigation
The detection logic identifies the creation or renaming of `.conf` files within standard Systemd service override paths. Investigating alerts involves:
- Comparing the new override file against the base unit file.
- Inspecting directives like `ExecStart`, `ExecStartPre`, `ExecStartPost`, `Environment`, `User`, `WorkingDirectory`, `OnCalendar`, and `WantedBy`.
- Tracing the originating process, parent process chain, and account context.
- Checking for related `systemctl` operations, such as `daemon-reload`, `enable`, or `restart`.
- Analyzing referenced scripts or binaries for suspicious content.

## False Positives
Legitimate administrative maintenance may involve creating override files to adjust startup order, resource limits, or environment settings. Verification should include confirming the creating process and user session context align with authorized administrative activity.
