---
title: Detection of Linux User Account Creation
slug: 2026-10-linux-add-user
description: Adversaries often create new user accounts on Linux systems using 'useradd' or 'adduser' to establish persistence and facilitate privilege escalation, which can be identified through process execution monitoring.
date: "2026-10-12T17:47:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - linux
  - edr
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Adversaries often create new user accounts to establish persistence on compromised hosts.
    confidence_band: high
rules:
  - title: Detect Linux User Account Creation
    description: Detects the creation of new user accounts on Linux systems using 'useradd' or 'adduser' command-line tools.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.001
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
    - action: Deploy the Linux user account creation Sigma rule.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic metadata.
  hunt_leads:
    - lead: Search historical logs for 'useradd' or 'adduser' activity to establish a baseline of normal administrative provisioning.
      technique_id: T1136.001
      data_needed:
        - Process execution logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Standard persistence detection workflow.
  mitigation_plan:
    - priority: short_term
      action: Implement strict access controls and audit logging for system configuration files like /etc/passwd.
      owner: IT Operations
      addresses: T1136.001
      evidence: Standard security hardening.
---

The creation of new local user accounts on Linux systems is a common mechanism for adversaries to maintain long-term persistence after achieving initial access to a target host. Threat actors utilize standard utilities such as 'useradd' or 'adduser' to add unauthorized accounts, often with elevated privileges, to ensure they can regain access if their initial entry point is neutralized. This activity is a significant indicator of potential compromise, as it deviates from standard system administration workflows. Defenders should monitor for these specific command-line executions via EDR telemetry to differentiate between legitimate administrative account provisioning and malicious unauthorized activity. Detection engineers should correlate these events with parent process information, such as suspicious shell processes or web server child processes, to increase the fidelity of the alerts.

## Impact

Successful creation of unauthorized user accounts allows attackers to maintain persistence, bypass credential rotation policies, escalate privileges, and gain a foothold for lateral movement across the internal network. If left undetected, this allows attackers to remain active within the environment for extended periods, significantly increasing the risk of data exfiltration and further system degradation.

## Recommendation

Prioritize the identification of unauthorized account creation by implementing telemetry monitoring for process execution on Linux endpoints.

- Deploy the provided Sigma rule to your SIEM environment to alert on 'useradd' or 'adduser' process executions.
- Integrate Sysmon for Linux or equivalent EDR process telemetry into your SIEM to ensure visibility into process creation events (Event ID 1).
- Baseline expected administrative account creation activity to tune the detection and reduce false positives.
- Investigate the parent process of any detected 'useradd' or 'adduser' execution to determine if the process originated from an interactive shell or a suspicious background process.
