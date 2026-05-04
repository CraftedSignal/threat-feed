---
title: Multiple Logon Failure Followed by Logon Success
slug: 2024-01-09-multiple-logon-failure-success
description: This rule identifies potential password guessing/brute force activity from a single address, followed by a successful logon, indicating that an attacker may have compromised an account by brute-forcing login attempts across multiple users.
date: "2024-01-09T14:00:00Z"
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
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_bruteforce_multiple_logon_failure_followed_by_success.toml
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
rules:
  - title: Multiple Logon Failures Followed by Success - Event ID 4625/4624
    description: Detects multiple logon failures (4625) followed by a successful logon (4624) from the same source IP, indicating potential brute-force activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - authentication
      - windows
  - title: Detect Multiple Logon Failures from Same Source IP
    description: Detects multiple failed login attempts from the same source IP address, indicative of brute-force attempts.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - authentication
      - windows
rules_count: 2
---

This detection rule focuses on identifying brute-force or password guessing attacks against Windows systems. It detects multiple failed logon attempts originating from the same source IP address, followed by a successful logon. This pattern suggests an attacker attempting to guess credentials to gain unauthorized access to an account. The rule leverages Windows Security Event Logs to monitor authentication events. This activity is important for defenders because successful brute-force attacks can lead to account compromise, data breaches, and further malicious activities within the network. The rule uses EQL and analyzes `logs-system.security*`, `logs-windows.forwarded*`, and `winlogbeat-*` indices.

## Attack Chain

1. The attacker initiates multiple failed logon attempts to a Windows system using various username and password combinations. These attempts originate from a single source IP address and target network logon types.
2. The system records each failed logon attempt as a Windows Security Event Log event (Event ID 4625). The event includes information about the source IP address, target username, and failure reason.
3. After several failed attempts, the attacker guesses the correct password for a valid user account.
4. The system records a successful logon event (Event ID 4624) for the compromised account, originating from the same source IP address as the previous failed attempts, also via a network logon type.
5. The attacker gains initial access to the target system using the compromised account.
6. The attacker may then attempt to escalate privileges or move laterally within the network, using the compromised account to access additional resources or systems.

## Impact

A successful brute-force attack can lead to unauthorized access to sensitive data, system compromise, and further malicious activities within the network. Compromised accounts can be used to escalate privileges, move laterally, and deploy ransomware. The severity depends on the privileges of the compromised account and the sensitivity of the data it can access.

## Recommendation

*   Enable Audit Logon to generate the necessary events (4624, 4625) in the Windows Security Event Logs for the detection rule to function. Reference: [https://ela.st/audit-logon](https://ela.st/audit-logon).
*   Deploy the provided Sigma rule to your SIEM to detect multiple logon failures followed by a successful logon. Tune the rule based on your environment and baseline activity.
*   Investigate any triggered alerts to determine the scope of the compromise and take appropriate remediation steps.
*   Consider implementing multi-factor authentication (MFA) to mitigate the risk of brute-force attacks.
*   Monitor network traffic for suspicious activity originating from the source IP address associated with the brute-force attempts.
*   Review and enforce strong password policies to reduce the likelihood of successful password guessing.
