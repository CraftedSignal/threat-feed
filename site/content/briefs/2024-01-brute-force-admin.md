---
title: Privileged Account Brute Force Detection
slug: 2024-01-brute-force-admin
description: Multiple consecutive logon failures targeting admin accounts from the same source IP address within a short timeframe indicates potential brute-force activity targeting privileged accounts on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - brute-force
  - credential-access
  - windows
vendors:
  - Microsoft
products:
  - Windows
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
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
  - https://attack.mitre.org/techniques/T1110/
rules:
  - title: Detect Brute Force of Admin Accounts
    description: Detects a high number of failed logon attempts targeting accounts with 'admin' in the username from a single source IP, indicating potential brute-force activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1110.001
    data_sources:
      - authentication
      - windows
  - title: Detect Brute Force of Admin Accounts - User Lockout
    description: Detects multiple failed login attempts followed by a user lockout event for admin accounts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1110.001
    data_sources:
      - authentication
      - windows
rules_count: 2
---

This threat brief addresses the risk of brute-force attacks targeting privileged accounts on Windows systems. Attackers often attempt to guess passwords to gain unauthorized access, particularly targeting accounts with "admin" in their username. This activity typically involves a single source IP address generating numerous failed login attempts against multiple accounts within a short period. Successful brute-force attacks against privileged accounts can lead to significant damage, including data theft, system compromise, and disruption of services. This detection strategy focuses on identifying such activity to enable timely intervention and prevent further escalation. The detection logic analyzes Windows Security Event Logs for failed network logon attempts.

## Attack Chain

1.  The attacker identifies a target system with accessible network services, such as SMB or RDP, commonly exposed on Windows systems.
2.  The attacker initiates a series of network logon attempts using various username and password combinations.
3.  The attacker focuses on accounts with the substring "admin" in the username, indicating a potential administrative or privileged account.
4.  The system records failed logon events (Event ID 4625) in the Windows Security Event Logs.
5.  The attacker repeats failed login attempts, attempting to bypass account lockout policies.
6.  If a successful login occurs, the attacker gains initial access to the compromised account.
7.  The attacker may attempt to escalate privileges or move laterally within the network.
8.  The attacker achieves their objective, such as data exfiltration, installing malware, or disrupting services.

## Impact

A successful brute-force attack on privileged accounts can lead to severe consequences, including unauthorized access to sensitive data, complete system compromise, and disruption of critical services. The impact can range from data breaches and financial losses to reputational damage and regulatory fines. The severity depends on the level of access granted to the compromised account and the attacker's subsequent actions.

## Recommendation

*   Deploy the Sigma rule "Detect Brute Force of Admin Accounts" to your SIEM to detect the attack (rule.title). Enable Windows Security Event Logs to ensure the rule has the required data (rule.logsource).
*   Investigate systems generating numerous failed logon attempts, as identified by the Sigma rule. Focus on source IP addresses and target usernames.
*   Review and enforce strong password policies, including complexity requirements and account lockout thresholds, to mitigate the risk of brute-force attacks.
*   Monitor network traffic for suspicious login activity and consider implementing multi-factor authentication for privileged accounts.
*   Implement the Osquery queries detailed in the source to enumerate potentially compromised accounts and investigate for anomalous behavior.
