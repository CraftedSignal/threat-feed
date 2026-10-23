---
brief_id: brief-2026-10-23-linux-openssl-persistence
event_id: brief-2026-10-23-linux-openssl-persistence
revision: 1
activity_at: "2026-10-23T14:41:58Z"
title: 'Linux: Unauthorized use of OpenSSL for password hash generation'
slug: 2026-10-linux-openssl-persistence
description: Adversaries may utilize the OpenSSL utility to generate password hashes for creating unauthorized local accounts or modifying existing credentials to maintain persistence on compromised Linux systems.
date: "2026-10-23T14:41:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - persistence
  - linux
  - credential-access
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may exploit OpenSSL to create hashes for unauthorized user accounts or modify existing ones, aiding in persistent access to Linux systems.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.001
    subtechnique_name: Local Account
    evidence: This rule detects the usage of the openssl binary to generate password hashes on Linux systems... to generate password hashes for new user accounts.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_openssl_passwd_hash_generation.toml
rules:
  - title: Detect Suspicious OpenSSL Password Hash Generation
    description: Detects the use of the openssl binary with the passwd argument to generate password hashes, excluding help flags, which may indicate unauthorized account manipulation or persistence efforts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
      - T1136.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for historical execution of 'openssl passwd' to identify baseline activity vs anomalies
      technique_id: T1098
      data_needed:
        - Process command line logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Identify the user account associated with the process execution to determine if the action was performed by a legitimate user or a potential adversary.
  mitigation_plan:
    - priority: medium
      action: Review user account activity and verify all created accounts are authorized
      owner: System Administrators
      addresses: T1136.001
      evidence: Conduct a thorough review of user accounts on the affected system to identify any unauthorized accounts
---

The OpenSSL command-line utility provides functionality for cryptographic operations, including the generation of password hashes via the 'passwd' subcommand. Attackers frequently leverage this capability during post-exploitation to manipulate local accounts, such as creating new privileged users or resetting passwords for existing accounts to ensure continued access to the target host.

## Impact

Successful exploitation allows for persistent unauthorized access to the Linux system. This facilitates account manipulation (T1098) and local account creation (T1136.001), potentially enabling attackers to bypass standard authentication controls or establish backdoors.

## Recommendation

Deploy process-creation monitoring to capture 'openssl' executions. Baseline all administrative scripts and service accounts that legitimately use 'openssl passwd' for provisioning or system maintenance to reduce noise. Investigate any instances where this command is executed by non-administrative users or from unexpected parent processes.
