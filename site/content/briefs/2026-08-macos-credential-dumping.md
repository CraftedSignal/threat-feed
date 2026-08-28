---
title: Detection of Credential Dumping via macOS Built-In Utilities
slug: 2026-08-macos-credential-dumping
description: Adversaries abuse native macOS utilities like 'dscl', 'mkpassdb', and 'defaults' to extract user password hashes from ShadowHashData or system plist files to facilitate credential cracking and lateral movement.
date: "2026-08-28T21:07:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - macos
  - edr
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Adversaries may attempt to dump credentials to obtain account login information in the form of a hash.
    confidence_band: high
references:
  - https://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored
  - https://www.unix.com/man-page/osx/8/mkpassdb/
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/credential_access_dumping_hashes_bi_cmds.toml
rules:
  - title: Detect Dumping Account Hashes via macOS Built-In Commands
    description: Detects the use of macOS built-in binaries like dscl, mkpassdb, or defaults to dump password hashes, or the use of file reading tools to access user plist files containing credential data.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.008
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for suspicious use of dscl, mkpassdb, and plist access.
      owner: Detection Engineering
      due: 48h
      evidence: Detection rule provided in the brief.
  hunt_leads:
    - lead: Search historical process execution logs for instances of 'mkpassdb' or 'dscl' usage referencing 'ShadowHashData'.
      technique_id: T1003.008
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Observed TTP identified in the source rule.
  mitigation_plan:
    - priority: short_term
      action: Review access permissions for the /var/db/dslocal/nodes/Default/users/ directory and restrict execution of sensitive binaries to administrative accounts.
      owner: IT Operations
      addresses: T1003.008
      evidence: Sensitive path identified in source documentation.
---

Adversaries targeting macOS environments often attempt to escalate privileges or move laterally by extracting user account hashes. This activity leverages built-in system utilities that possess the necessary permissions to access sensitive authentication artifacts. Specifically, tools such as `defaults`, `mkpassdb`, and `dscl` are utilized to query the `ShadowHashData` attribute, or common file-processing binaries like `cat`, `strings`, or `plutil` are used to read user-specific configuration files located in `/var/db/dslocal/nodes/Default/users/`. Once these hashes are retrieved, attackers can perform offline brute-force attacks to recover cleartext passwords. Given that these utilities are standard components of the macOS operating system, defenders must monitor for anomalous execution patterns, particularly when these tools are used to access files containing sensitive authentication material. This detection approach is essential for identifying credential access early in the attack lifecycle.

## Impact

Successful extraction of local user hashes on macOS allows attackers to perform offline password cracking, potentially compromising user accounts. In enterprise environments, if these accounts share credentials with other systems or services, the breach can lead to unauthorized access to sensitive data, privilege escalation, and lateral movement across the internal network.

## Recommendation

- Deploy the provided detection rules to your EDR or SIEM solution to identify unauthorized access to ShadowHashData and user plist files.
- Review and baseline administrative scripts and maintenance tools that legitimately access these system files to reduce false positive alerts.
- Enforce strong, unique password policies and implement multi-factor authentication to mitigate the impact of cracked user hashes.
- Isolate systems showing evidence of unauthorized hash dumping and initiate an incident response process to audit account access and check for lateral movement.
