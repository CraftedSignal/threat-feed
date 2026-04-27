---
title: Linux Cron File Creation for Persistence
slug: 2024-01-03-linux-cron-persistence
description: An attacker may create new cron files in cron directories to establish persistence on a Linux system, potentially leading to privilege escalation and arbitrary code execution.
date: "2024-01-03T14:30:00Z"
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://github.com/microsoft/MSTIC-Sysmon/blob/f1477c0512b0747c1455283069c21faec758e29d/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml
  - https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/
  - https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
  - https://snehbavarva.medium.com/privilege-escalation-techniques-series-linux-cron-jobs-a5b797b424b4
rules:
  - title: Detect New Cron File Creation
    description: Detects the creation of cron files in Cron directories, which could indicate potential persistence mechanisms being established by an attacker.
    platform: sigma
    severity: low
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1053.003
    data_sources:
      - file_event
      - linux
  - title: Suspicious Cron File Modification
    description: Detects modification of cron files, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Attackers can leverage cron jobs to schedule malicious tasks for persistence, privilege escalation, and execution of arbitrary code on compromised Linux systems. This involves creating or modifying cron files in specific directories such as `/etc/cron.d/`, `/etc/cron.daily/`, `/var/spool/cron/crontabs/`, and others. The creation of unexpected cron files by non-administrative users or during suspicious timeframes warrants investigation. While not all cron file creations are malicious, the…
