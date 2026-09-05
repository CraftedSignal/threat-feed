---
title: Detection of Linux Crontab Task Enumeration
slug: 2026-09-linux-crontab-enumeration
description: Adversaries often execute 'crontab -l' to enumerate existing scheduled tasks, enabling the discovery of persistence mechanisms, legitimate job hijacking targets, or privilege escalation opportunities.
date: "2026-09-05T00:02:12Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - persistence
  - execution
  - linux
  - living-off-the-land
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries may use this information to identify persistence mechanisms, scheduled execution, or potential privilege escalation opportunities.
    confidence_band: high
rules:
  - title: Detect Linux Crontab Enumeration via crontab -l
    description: Detects the use of the crontab command with the list parameter, which is a common enumeration technique for finding scheduled tasks.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - persistence
    techniques:
      - T1053.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the crontab -l detection rule.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic logic for T1053.003.
  hunt_leads:
    - lead: Analyze process execution logs for crontab -l combined with suspicious parent processes.
      technique_id: T1053.003
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Analytic story highlights this as a Linux persistence technique.
  mitigation_plan:
    - priority: medium
      action: Review cron job configurations for unauthorized entries.
      owner: IT Operations
      addresses: T1053.003
      evidence: Enumeration often leads to persistence modification.
---

Adversaries targeting Linux systems frequently leverage the `crontab -l` command to perform reconnaissance on scheduled tasks. By listing the contents of a user's crontab, an attacker can identify existing persistence mechanisms, understand system maintenance workflows, or locate credentials and environment variables stored in scripts executed via cron. While this behavior is indicative of T1053.003 (Scheduled Task/Job: Cron), it is also a common administrative activity used for system automation and monitoring. Detection strategies must differentiate between benign system administration and potentially malicious enumeration by correlating the command execution with the invoking user's context, the parent process tree, and the execution environment. This technique is often observed in the context of broader post-exploitation activities, including privilege escalation and the maintenance of persistence.

## Attack Chain

1. Attacker gains initial access to the Linux host via exploitation or credential theft.
2. Attacker initiates process enumeration to understand the environment.
3. Attacker executes `crontab -l` to dump current cron jobs for the active user.
4. Attacker analyzes the output to identify scripts, file paths, and potential triggers.
5. Attacker targets a frequently executed script or task for modification.
6. Attacker overwrites the target script or modifies the crontab to maintain persistence or escalate privileges.

## Impact

Successful enumeration of scheduled tasks provides an attacker with critical visibility into host maintenance and security patterns, significantly increasing the likelihood of successful persistence and privilege escalation. Failure to monitor this activity may allow attackers to operate undetected within the environment for extended periods.

## Recommendation

Deploy the detection rule below to monitor for `crontab -l` execution. Because this command is frequently used for legitimate administrative purposes, security teams should tune the rule by allowlisting known service accounts and administrative management processes. Enable Sysmon for Linux or Cisco Isovalent instrumentation to capture the parent process, process GUID, and command-line arguments required for accurate scoping.
