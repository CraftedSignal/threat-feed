---
title: Linux Persistence via Sudoers.d File Manipulation
slug: 2026-04-sudoers-persistence
description: Attackers can achieve persistence and privilege escalation on Linux systems by creating or modifying files in the /etc/sudoers.d/ directory to grant unauthorized users or groups sudo privileges.
date: "2026-04-27T23:12:30Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - persistence
  - privilege-escalation
  - linux
  - sudoers
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml
rules:
  - title: Detect Sudoers.d File Creation
    description: Detects the creation of new files in the sudoers.d directory, which may indicate an attempt to establish unauthorized privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1548.003
    data_sources:
      - file_event
      - linux
  - title: Detect Sudoers.d File Modification
    description: Detects modifications to existing files in the sudoers.d directory, which could indicate an attempt to modify sudo privileges.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1548.003
    data_sources:
      - file_event
      - linux
  - title: Detect Dpkg Temporary Sudoers.d File
    description: Detects the creation of temporary dpkg files in the sudoers.d directory.
    platform: sigma
    severity: informational
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1548.003
    data_sources:
      - file_event
      - linux
rules_count: 3
---

The sudoers.d directory on Linux systems is designed to allow administrators to manage sudo privileges by adding individual files rather than modifying the main /etc/sudoers file. An attacker who gains initial access to a system can exploit this by creating or modifying files within this directory to grant themselves or other malicious actors elevated privileges. This can be done to ensure persistent access, even if other initial access methods are detected and remediated. The modification of…
