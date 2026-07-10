---
title: Cisco ASA User Account Deletion
slug: 2024-01-03-cisco-asa-account-deletion
description: Detection of user account deletion on Cisco ASA devices, potentially indicating adversary attempts to cover tracks, disrupt incident response, or deny administrator access.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cisco_asa
  - account_deletion
  - defense_evasion
vendors:
  - Cisco
products:
  - Cisco ASA
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1531
    technique_name: Account Access Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-500000-to-520025.html#con_4773969
rules:
  - title: Cisco ASA - User Account Deletion Detected
    description: Detects deletion of user accounts on Cisco ASA devices based on syslog message ID 502102.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.008
      - T1531
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA - Privilege Level 15 Account Deletion
    description: Alert when an account with privilege level 15 (highest level) is deleted on a Cisco ASA, potentially indicating a high-impact compromise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.008
      - T1531
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This brief focuses on the detection of user account deletions on Cisco ASA devices, a tactic commonly employed by adversaries to obfuscate their activities within a compromised network. The deletion of user accounts, particularly those with elevated privileges (level 15), can serve to remove evidence of malicious actions, hinder incident response efforts, or deny legitimate administrators access to critical systems. This activity can also be a sign of hiding temporary account creation used during a compromise. This analytic relies on monitoring Cisco ASA logs for message ID 502102, which is triggered upon the deletion of a local user account. This event captures valuable information, including the username, privilege level, and the administrator responsible for the deletion. It is crucial to investigate unexpected or unauthorized account deletions, especially those occurring outside of normal business hours or involving privileged accounts.

## Attack Chain

1.  Initial Access: Adversary gains initial access to a system with valid credentials or exploits a vulnerability.
2.  Privilege Escalation: The attacker elevates privileges to gain administrative access to the Cisco ASA device.
3.  Account Discovery: The attacker enumerates existing user accounts on the Cisco ASA device to identify potential targets for deletion.
4.  Account Deletion: The adversary deletes a local user account on the Cisco ASA device, generating syslog message ID 502102.
5.  Log Manipulation (Optional): Attempts to further cover tracks by disabling logging or manipulating the ASA's logging configuration.
6.  Persistence (Obstructed): By deleting accounts, legitimate user's persistence is removed and access to the system is revoked.
7.  Defense Evasion: The attacker attempts to evade detection by deleting accounts used during the compromise.

## Impact

Successful deletion of user accounts can disrupt incident response efforts by removing valuable forensic data and hindering the ability to track the attacker's activities. It can also lead to denial-of-service for legitimate users who rely on those accounts for access. Privileged account deletion can result in significant operational disruption and potential data breaches due to loss of control over critical systems.

## Recommendation

*   Enable and forward Cisco ASA syslog data, specifically message ID 502102, to your SIEM for analysis as detailed in the "how_to_implement" section.
*   Deploy the Sigma rule "Cisco ASA - User Account Deletion Detected" to your SIEM and tune the filter list to exclude known benign account deletions.
*   Investigate any instances of message ID 502102, cross-referencing with HR records and change management systems to identify unauthorized account deletions as described in the description.
*   Monitor ASA logging configurations for unauthorized changes that could indicate log manipulation attempts.
*   Review the "references" link to understand the context of ASA message ID 502102 within the overall ASA syslog architecture.
