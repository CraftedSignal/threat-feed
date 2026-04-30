---
title: Potential snap-confine Privilege Escalation via CVE-2026-3888
slug: 2026-03-snap-confine-lpe
description: An unprivileged user may exploit CVE-2026-3888 to escalate privileges to root by creating malicious files in the /tmp/.snap directory.
date: "2026-03-20T08:34:17Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - linux
  - cve-2026-3888
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root
  - https://cdn2.qualys.com/advisory/2026/03/17/snap-confine-systemd-tmpfiles.txt
rules:
  - title: Detect Non-Root File Creation in Snap Temporary Directories
    description: Detects file creation by non-root users in /tmp/.snap or /tmp/snap-private-tmp/*/tmp/.snap, indicative of CVE-2026-3888 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-3888
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Snap Confine Execution with Suspicious Arguments
    description: Detects snap-confine execution with arguments pointing to the /tmp/.snap directory, potentially indicating exploitation of CVE-2026-3888.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-3888
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-3888 is a local privilege escalation vulnerability affecting Ubuntu systems using snap-confine. The vulnerability exists because systemd-tmpfiles may delete the /tmp/.snap directory, which is normally created by root. An unprivileged user can then recreate this directory and populate it with attacker-controlled files. The snap-confine utility, during subsequent snap sandbox initialization, may then bind-mount or trust these attacker-controlled paths. This can lead to the manipulation…
