---
title: Detection of New User Account Creation on Linux
slug: 2026-10-linux-auditd-user-add
description: This detection monitors for the creation of new user accounts on Linux systems, a common technique employed by adversaries to establish persistence on compromised hosts.
date: "2026-10-12T17:47:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - auditd
  - account-creation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: This activity is significant as adversaries often create new user accounts to establish persistence on compromised hosts.
    confidence_band: high
rules:
  - title: Detect User Account Creation on Linux
    description: Detects the creation of new user accounts via useradd or adduser commands, which is often a sign of attacker persistence.
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
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM and tune against administrative baselines.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for user account creation.
  hunt_leads:
    - lead: Search for recently created user accounts in /etc/passwd or /etc/shadow that do not align with known deployment logs.
      technique_id: T1136.001
      data_needed:
        - System user list logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries create local accounts to maintain persistence.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict policies and logging for administrative user account management.
      owner: IT Operations
      addresses: T1136.001
      evidence: Persistence mitigation best practices.
---

Adversaries often create new user accounts to establish persistence after compromising a Linux host. This activity allows attackers to maintain long-term access, escalate privileges, and bypass existing security controls that might be tied to specific user sessions. This detection identifies the execution of user account creation utilities, specifically "useradd" and "adduser," by leveraging Linux Auditd "proctitle" logs. The ability to track the creation of local accounts is vital for defenders to identify unauthorized administrative actions that may indicate a breach. This analytic is designed for security operations teams using EDR or host-based audit logging to monitor for anomalous account creation events.

## Impact

Successful account creation by an unauthorized actor provides a stable, persistent foothold on a system. This can lead to lateral movement, data exfiltration, and long-term control over the compromised host. If left undetected, attackers can leverage these accounts to perform further system reconnaissance and facilitate additional malicious activities without relying solely on the original initial access vector.

## Recommendation

* Ingest Auditd SYSCALL, EXECVE, and PROCTITLE events using the Splunk Add-on for Unix and Linux.
* Normalize ingested logs to match the Common Information Model (CIM) to ensure consistency and improve detection efficacy.
* Deploy the Sigma rule provided in this brief to detect the execution of "useradd" or "adduser" utilities.
* Update filter macros within your SIEM to exclude known legitimate administrative activity or automated provisioning scripts to reduce false positives.
