---
title: GCP Password Spraying Detection
slug: 2024-01-gcp-password-spray
description: A single source IP is failing to authenticate into Google Workspace with multiple valid users, potentially indicating a Password Spraying attack.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gcp
  - password-spraying
  - cloud
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Use Legitimate Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://cloud.google.com/blog/products/identity-security/how-google-cloud-can-help-stop-credential-stuffing-attacks
  - https://www.slideshare.net/dafthack/ok-google-how-do-i-red-team-gsuite
  - https://attack.mitre.org/techniques/T1110/003/
  - https://www.blackhillsinfosec.com/wp-content/uploads/2020/05/Breaching-the-Cloud-Perimeter-Slides.pdf
rules:
  - title: GCP Unusual Number of Failed Authentications From IP
    description: Detects a single source IP failing to authenticate into Google Workspace with multiple valid users, potentially indicating a Password Spraying attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
      - linux
  - title: GCP Valid Usernames Targeted after Password Spraying
    description: Identify the google accounts that were part of the password spraying attack
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic detects potential password spraying attacks against Google Workspace accounts. Password spraying involves an attacker attempting to authenticate to multiple accounts with a list of commonly used passwords. The attack leverages Google Workspace login failure events to identify source IPs exhibiting an unusually high number of failed login attempts across multiple user accounts. The detection calculates the standard deviation of unique accounts per source IP and flags IPs exceeding a threshold based on the 3-sigma rule. This activity is a significant indicator of attackers attempting to gain initial access to the environment, potentially leading to unauthorized access, data breaches, or further exploitation. The detection logic is based on failed login events, specifically `event.type = login` and `event.name = login_failure`.

## Attack Chain

1. The attacker identifies a list of valid usernames within the target Google Workspace environment. This may be achieved through OSINT techniques or prior breaches.
2. The attacker crafts login requests to the Google Workspace login endpoint, using a common password and iterating through the list of usernames.
3. Google Workspace records login failure events, including the source IP address, attempted username, and authentication method.
4. The detection analytic aggregates these failed login events, grouping them by source IP address and calculating the number of unique user accounts targeted from each IP within a 5-minute window.
5. The analytic calculates the average and standard deviation of unique accounts targeted per source IP over time.
6. A source IP is flagged as suspicious if it exceeds a threshold calculated using the 3-sigma rule (average + 3 * standard deviation) and has attempted to authenticate to more than 10 unique accounts.
7. If successful, the attacker gains initial access to a valid user account within the Google Workspace environment.
8. The attacker may then escalate privileges, move laterally within the environment, or exfiltrate sensitive data.

## Impact

A successful password spraying attack can lead to widespread compromise of Google Workspace accounts. Attackers can gain access to sensitive data stored in email, documents, and other Google Workspace applications. This can result in data breaches, financial loss, and reputational damage. The impact can range from a few compromised accounts to a complete takeover of the organization's Google Workspace environment. The Black Hills Information Security reference details real-world examples of cloud perimeter breaches.

## Recommendation

*   Deploy the Sigma rule `GCP Unusual Number of Failed Authentications From IP` to your SIEM and tune the `span` and `unique_accounts` threshold values for your specific environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on the source IP address and the user accounts targeted.
*   Implement multi-factor authentication (MFA) for all Google Workspace accounts to mitigate the risk of password-based attacks.
*   Monitor Google Workspace logs for unusual login activity, such as logins from unfamiliar locations or devices.
*   Consider using Google Cloud's Identity Protection features to detect and prevent credential stuffing attacks, as mentioned in the Google Cloud blog reference.
