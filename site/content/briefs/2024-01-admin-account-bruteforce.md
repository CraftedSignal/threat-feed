---
title: Windows Admin Account Brute Force Detection
slug: 2024-01-admin-account-bruteforce
description: This rule identifies potential password guessing/brute force activity from a single source IP targeting multiple Windows accounts with 'admin' in the username, indicating an attempt to compromise privileged accounts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - brute-force
  - windows
vendors:
  - Microsoft
products:
  - Windows Security Event Logs
affected_os:
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
  - https://attack.mitre.org/techniques/T1110/001/
  - https://attack.mitre.org/techniques/T1110/003/
rules:
  - title: Detect Windows Admin Account Brute Force
    description: Detects brute force attempts against multiple Windows accounts containing 'admin' in the username from the same source IP address.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1110.001
      - T1110.003
    data_sources:
      - authentication
      - windows
  - title: Detect High Volume of Failed Logons from Single Source IP
    description: Detects a high volume of failed logon attempts from a single source IP address, potentially indicating a brute-force attack.
    platform: sigma
    severity: low
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

This detection rule, originally created on 2020-08-29 and last updated on 2026-05-04, identifies potential brute-force attempts against Windows systems. It focuses on scenarios where an attacker attempts to guess passwords for multiple accounts containing the term "admin" in their usernames, suggesting an attempt to compromise privileged accounts. The rule aggregates failed logon events to detect this activity. This is important for defenders as successful brute-force attacks can lead to unauthorized access, data breaches, and other malicious activities. The rule leverages Windows Security Event Logs and requires Audit Logon to be enabled.

## Attack Chain

1. The attacker attempts to gain initial access to the target network.
2. The attacker identifies potential target accounts with "admin" in their username.
3. The attacker initiates a series of network logon attempts using various password combinations (T1110.001, T1110.003).
4. The Windows system records failed logon events (Event ID 4625) in the Security Event Logs.
5. The detection rule aggregates these failed logon events, filtering out known noisy failure codes.
6. If the number of failed attempts against distinct "admin" accounts from the same source IP within a 60-second window exceeds a threshold (50 attempts against 2 distinct usernames), the rule triggers an alert.
7. The attacker, if successful, gains unauthorized access to the targeted admin account.
8. With access to an admin account, the attacker can perform a wide range of malicious activities, including privilege escalation, data exfiltration, and system compromise.

## Impact

Successful brute-force attacks on administrator accounts can lead to significant damage. Attackers gaining access can escalate privileges, install malware, access sensitive data, or disrupt critical systems. This can result in data breaches, financial losses, and reputational damage. While specific victim counts are not provided, the rule's focus on privileged accounts indicates a high potential for severe impact on organizations.

## Recommendation

*   Enable Audit Logon to generate the necessary Windows Security Event Logs. Refer to the setup instructions at https://ela.st/audit-logon.
*   Deploy the Sigma rule "Detect Windows Admin Account Brute Force" to your SIEM and tune the threshold parameters (failed_auth_count, count_distinct_user_name) for your environment.
*   Investigate alerts triggered by the Sigma rule, focusing on the source IP address, targeted usernames, and logon failure reason codes.
*   Review and strengthen password policies to prevent password guessing attacks (T1110).
*   Monitor network traffic for suspicious logon attempts from external IP addresses to internal systems.
