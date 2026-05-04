---
title: Multiple Logon Failure from the Same Source Address
slug: 2024-01-multiple-logon-failure
description: Detection of multiple consecutive logon failures from the same source address within a short time interval on Windows systems, indicating potential brute force or password spraying attacks targeting multiple user accounts.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - brute-force
  - password-spraying
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
  - https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624
  - https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity
  - https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638
rules:
  - title: Multiple Failed Logon Attempts from Single Source IP
    description: Detects a high number of failed logon attempts from the same source IP address within a short time frame, indicative of brute-force or password spraying attacks.
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
  - title: Failed Network Logon with Multiple Usernames
    description: Identifies failed network logon attempts targeting multiple usernames from the same source, indicating password spraying.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1110.003
    data_sources:
      - authentication
      - windows
rules_count: 2
---

This detection rule identifies potential password guessing or brute force activity against Windows systems. It focuses on detecting a high number of failed network logon attempts originating from a single source IP address within a short time frame. The rule analyzes Windows Security Event Logs, specifically looking for event category "authentication" and event action "logon-failed". By aggregating failed authentication counts within a 60-second window and filtering out common authentication misconfiguration errors, the rule aims to pinpoint suspicious activity indicative of credential access attempts. This is important for defenders as it highlights potential breaches or malicious actors attempting to compromise user accounts via brute-force or password spraying attacks.

## Attack Chain

1.  The attacker initiates a network connection to a Windows system, likely targeting a service such as SMB or RDP.
2.  The attacker attempts to authenticate using a list of usernames and passwords or commonly used passwords, generating failed logon attempts (Event ID 4625).
3.  The Windows system logs the failed authentication attempts in the Security Event Log.
4.  The detection rule monitors the Security Event Log for failed logon events (event.category == "authentication" and event.action == "logon-failed").
5.  The rule aggregates the number of failed logon attempts from the same source IP address within a 60-second time window.
6.  If the number of failed attempts exceeds a threshold (e.g., 100) and involves multiple target usernames (Esql.count_distinct_target_user_name >= 2), the rule triggers a detection.
7.  The attacker may continue attempts after initial failures or pivot to successful credentials for lateral movement.
8.  Successful credential access can lead to privilege escalation, data exfiltration, or other malicious activities.

## Impact

Successful brute-force or password spraying attacks can lead to unauthorized access to user accounts and sensitive data. The impact can range from minor inconvenience to significant data breaches and financial losses, depending on the compromised accounts and the data they have access to. The rule aims to reduce the window of opportunity for attackers to gain a foothold in the environment.

## Recommendation

*   Enable Audit Logon to generate the necessary Windows Security Event Logs. Follow the setup instructions outlined in the rule documentation.
*   Deploy the Sigma rule "Multiple Logon Failure from the Same Source Address" to your SIEM and tune the threshold values (Esql.failed_auth_count and Esql.count_distinct_target_user_name) to minimize false positives in your environment.
*   Investigate any triggered alerts by examining the logon failure reason codes and the targeted user names as described in the rule's investigation guide.
*   Monitor network connections from the source IP address for any suspicious outbound traffic or lateral movement activity.
*   Review and enforce strong password policies to mitigate the risk of successful brute-force attacks.
