---
title: Cisco ASA User Account Lockout Detection
slug: 2024-01-cisco-asa-account-lockout
description: Detection of user account lockouts on Cisco ASA devices due to excessive failed authentication attempts, potentially indicating brute-force attacks, password spraying, or credential stuffing.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - authentication
  - brute_force
  - password_spraying
  - cisco_asa
vendors:
  - Cisco
products:
  - Cisco ASA
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-101001-to-199021.html#con_4769446
rules:
  - title: Cisco ASA - User Account Lockout Detected
    description: Detects user account lockouts on Cisco ASA devices based on message ID 113006.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
      - T1110.003
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA - Multiple Account Lockouts from Single Host
    description: Detects multiple account lockouts from a single host within a short time, suggesting password spraying.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This brief focuses on detecting account lockouts on Cisco ASA (Adaptive Security Appliance) devices. The increasing sophistication of cyberattacks means that organizations must monitor not just successful breaches, but also failed authentication attempts that may signal ongoing brute force attacks, password spraying campaigns, or credential stuffing attempts. The presence of these types of attacks indicate that credentials may have been compromised from external breaches and are being used to gain unauthorized access to network infrastructure. This analytic specifically leverages Cisco ASA message ID 113006, which signifies a user account lockout triggered by exceeding the permitted number of failed authentication attempts. This detection is crucial for defenders, as it enables timely response to potential unauthorized access attempts, protecting sensitive resources and maintaining network integrity.

## Attack Chain

1.  The attacker attempts to authenticate to the Cisco ASA using compromised credentials or by guessing passwords.
2.  The authentication attempts fail.
3.  The Cisco ASA logs message ID 113006, indicating a failed authentication attempt.
4.  The attacker continues to attempt authentication, exceeding the configured lockout threshold.
5.  The Cisco ASA locks the user account, logging message ID 113006 with details of the account lockout and the failure threshold.
6.  The detection rule triggers based on the 113006 event identifying the user account and originating host.
7.  Security team investigates the lockout event, looking for associated malicious activity.
8.  If confirmed malicious, the security team takes action to block the attacker and remediate the compromised account.

## Impact

Successful exploitation could lead to unauthorized access to the network, potentially leading to data breaches, service disruption, or further lateral movement within the network. While a single account lockout might seem minor, a series of lockouts, especially affecting privileged accounts, could indicate a coordinated attack. Organizations in all sectors are vulnerable, with financial services and healthcare being particularly attractive targets.

## Recommendation

*   Ingest Cisco ASA syslog data into Splunk via the Cisco Security Cloud TA to populate the `cisco_asa` macro.
*   Configure Cisco ASA devices to generate and forward message ID 113006 for account lockout events to Splunk.
*   Tune and deploy the Sigma rule "Cisco ASA - User Account Lockout Detected" to detect account lockouts.
*   Investigate alerts from the Sigma rule, focusing on privileged accounts, unusual source IP addresses, and multiple simultaneous lockouts.
*   Review and tune the lockout threshold on Cisco ASA devices based on your organization's security policies.
