---
title: Linux Cron File Creation for Persistence
slug: 2024-01-03-linux-cron-persistence
description: An attacker may create new cron files in cron directories to establish persistence on a Linux system, potentially leading to privilege escalation and arbitrary code execution.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
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

Attackers can leverage cron jobs to schedule malicious tasks for persistence, privilege escalation, and execution of arbitrary code on compromised Linux systems. This involves creating or modifying cron files in specific directories such as `/etc/cron.d/`, `/etc/cron.daily/`, `/var/spool/cron/crontabs/`, and others. The creation of unexpected cron files by non-administrative users or during suspicious timeframes warrants investigation. While not all cron file creations are malicious, the potential for abuse necessitates monitoring for anomalous activity. Detecting the creation of new cron files can help identify potential persistence mechanisms being deployed by malicious actors.

## Attack Chain

1. An attacker gains initial access to a Linux system, potentially through exploiting a vulnerability or using compromised credentials.
2. The attacker identifies cron job directories, such as `/etc/cron.d/` or `/var/spool/cron/crontabs/`.
3. The attacker creates a new cron file within one of these directories.
4. The cron file contains malicious commands or scripts designed to execute at a specific time or interval. This could include commands to download and execute malware or establish a reverse shell.
5. The cron daemon automatically executes the commands specified in the newly created cron file according to the defined schedule.
6. The attacker gains persistent access to the system, allowing them to maintain control even after reboots.
7. The attacker may escalate privileges by scheduling commands that run with elevated permissions.
8. The attacker uses the persistent access to perform further malicious activities, such as data exfiltration or lateral movement.

## Impact

Successful exploitation can grant attackers persistent access to compromised Linux systems, potentially leading to privilege escalation and unauthorized execution of arbitrary code. This can lead to data breaches, system compromise, and disruption of services. The impact is magnified if the compromised system has access to sensitive information or critical infrastructure.

## Recommendation

*   Deploy the Sigma rule "Detect New Cron File Creation" to your SIEM to detect the creation of cron files in cron directories and tune for your environment.
*   Monitor file creation events in cron directories such as `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.monthly/`, `/etc/cron.weekly/`, `/var/spool/cron/crontabs/`, and `/var/spool/cron/root` using file_event logs.
*   Baseline normal cron file creation activity and apply additional filters to reduce false positives based on the specific environment, as mentioned in the rule description.
