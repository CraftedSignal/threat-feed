---
title: Detection of Linux Data Destruction via rm Command
slug: 2026-09-linux-data-destruction
description: Detection engineers can identify potential data destruction attempts on Linux hosts by monitoring for the use of the 'rm' command with the '--no-preserve-root' flag, a technique utilized by the Awfulshred malware.
date: "2026-09-04T18:00:50Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Awfulshred
tags:
  - data-destruction
  - malware
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The following analytic detects the execution of a Unix shell command designed to wipe root directories on a Linux host.
    confidence_band: high
references:
  - https://cert.gov.ua/article/3718487
  - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/overview-of-the-cyber-weapons-used-in-the-ukraine-russia-war/
rules:
  - title: Detect Linux Data Destruction via rm
    description: Detects the use of the rm command with the --no-preserve-root flag, which is used to bypass protection and wipe root directories on Linux systems.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect rm --no-preserve-root execution.
      owner: Detection Engineering
      due: 24h
      evidence: Source documentation identifies this command-line as a data destruction indicator.
  hunt_leads:
    - lead: Search for historical logs of 'rm' commands containing '--no-preserve-root'.
      technique_id: T1485
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This command is a high-fidelity indicator of destructive intent.
---

This brief details the detection of a high-impact data destruction technique targeting Linux environments. The activity involves the execution of the Unix shell command 'rm' with the '--no-preserve-root' argument, which bypasses built-in safety protections designed to prevent the recursive deletion of the root file system. This specific command usage is a known behavior of the Awfulshred malware, which aims to inflict severe damage, including full system data loss and total service disruption. Monitoring for this command-line execution is essential for defenders, as it often marks the final stage of an intrusion where an attacker attempts to cripple the target system's integrity and forensic viability.

## Impact

Successful execution of this command leads to irreversible data loss and total system instability. Depending on the privileges of the executing process, this can result in the destruction of all files and directories on the local host. This technique is primarily observed in destructive cyber campaigns intended to disrupt critical infrastructure and corporate operations.

## Recommendation

Detection engineering teams should implement monitoring for process-creation events to catch this specific command pattern immediately.
- Deploy the provided Sigma rule to your SIEM and tune to ensure visibility into the 'rm' command-line arguments.
- Ensure that EDR or Sysmon for Linux is configured to log full command-line arguments, as 'rm' activity is a high-fidelity indicator of malicious intent.
- Alert on any instances where the 'rm' binary is executed by administrative or root-level service accounts with the '--no-preserve-root' flag.
