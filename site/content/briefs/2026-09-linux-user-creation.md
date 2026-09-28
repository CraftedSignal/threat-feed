---
title: Detection of Linux User Account Creation for Persistence
slug: 2026-09-linux-user-creation
description: Attackers frequently create new local user accounts on Linux systems to establish and maintain persistence following initial compromise.
date: "2026-09-28T16:10:27Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - linux
  - endpoint
  - detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Attackers may create new accounts (both local and domain) to maintain access to victim systems.
    confidence_band: high
references:
  - https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_linux_user_account_creation.toml
rules:
  - title: Linux User Account Creation
    description: Detects the successful creation of a new local user account on Linux systems via system authentication logs.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy rule to SIEM and baseline administrative user creation behavior
      owner: Detection Engineering
      due: 7d
      evidence: Rule documentation requires baseline to manage false positives
  hunt_leads:
    - lead: Identify all local user accounts created in the last 30 days
      technique_id: T1136.001
      data_needed:
        - System authentication logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Creation of new accounts is a standard persistence technique
---

The creation of new user accounts on Linux systems is a common technique used by threat actors to maintain unauthorized access to a compromised environment. By leveraging standard system utilities such as `useradd` or `adduser`, an adversary can establish a new local account that provides long-term persistence, bypasses session timeouts, and potentially grants higher-level privileges if added to groups like `sudo` or `wheel`. 

While account creation is a routine administrative task in enterprise environments, it remains a critical signal in security monitoring. Defenders should correlate these events with the identity performing the action and the context of the host to differentiate between legitimate IT provisioning and unauthorized persistent access attempts.

## Impact

Successful account creation allows adversaries to maintain persistence even if initial access credentials are changed or revoked. This can lead to persistent data exfiltration, lateral movement, or the staging of further malicious activity. If unauthorized accounts are not detected and remediated, the attacker maintains a persistent foothold in the environment until the account is explicitly identified and removed.

## Recommendation

- Deploy the provided detection logic to identify `useradd` and `adduser` activity across all Linux hosts.
- Establish a baseline of authorized administrative accounts and automated service accounts that legitimately perform user creation to reduce alert noise.
- When an alert triggers, use the provided Osquery queries to verify if the account is active, verify group memberships, and investigate the parent process tree for the process that initiated the user creation.
- Enable Filebeat System Module logs on all Linux endpoints to ensure the necessary audit telemetry reaches the SIEM.
