---
title: Azure AD Brute Force Attack Detected via High Failed Authentication Count
slug: 2024-01-azure-ad-brute-force
description: Detection of a potential brute-force attack against an Azure AD account, identified by a high number of failed authentication attempts within a short time frame, potentially leading to unauthorized access and data breaches.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - brute-force
  - credential-access
  - cloud
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://attack.mitre.org/techniques/T1110/
  - https://attack.mitre.org/techniques/T1110/001/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_high_number_of_failed_authentications_for_user.yml
rules:
  - title: Azure AD High Failed Authentications
    description: Detects a high number of failed Azure AD authentications for a single user, indicative of a brute-force or credential stuffing attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1110.001
    data_sources:
      - network_connection
      - azure
  - title: Azure AD Successful Login After Failed Attempts
    description: Detects a successful Azure AD login immediately following a series of failed authentication attempts, possibly indicating a successful brute-force attack.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1110.001
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This brief addresses the detection of potential brute-force attacks targeting Azure Active Directory (AD) accounts. The detection focuses on identifying accounts that exhibit a high number of failed authentication attempts within a 10-minute window. Specifically, it monitors Azure AD SignInLogs for error code 50126 combined with unsuccessful authentication attempts. While the specific threat actor is unknown, this activity is consistent with credential stuffing or brute-force attacks, which can compromise user accounts. The default threshold is set to 20 failed attempts, which should be tuned to the specific environment. This alert logic was released on 2026-04-15 within Splunk's Security Content Update.

## Attack Chain

1. The attacker identifies a target Azure AD account, often through open-source intelligence or previously compromised data.
2. The attacker initiates authentication attempts against the Azure AD endpoint using the targeted username and a list of potential passwords.
3. Each failed authentication attempt generates a SignInLog event in Azure AD with error code 50126 and a status indicating unsuccessful authentication.
4. The attacker continues to submit authentication requests with different password variations within a 10-minute timeframe.
5. The system logs multiple failed authentication attempts from the same user account within the defined time window.
6. If the brute-force attack succeeds, the attacker gains unauthorized access to the targeted account.
7. The attacker leverages the compromised account to access sensitive resources, such as emails, files, and applications within the Azure AD environment.
8. The attacker may escalate privileges, move laterally within the environment, and exfiltrate data or deploy malicious payloads.

## Impact

A successful brute-force attack against an Azure AD account can lead to significant damage. Compromised accounts can be used to access sensitive data, disrupt business operations, and launch further attacks within the organization. Depending on the user's role, the attacker could gain access to critical systems and data, leading to data breaches, financial losses, and reputational damage. The number of potential victims is directly related to the number of accounts exposed and the extent of access granted to those accounts within the Azure AD environment.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD High Failed Authentications` to your SIEM and tune the threshold (currently 20 failed attempts in 10 minutes) based on your environment's baseline authentication behavior.
*   Enable and review Azure AD SignInLogs with category `SignInLogs` to ensure the required data is being collected and ingested.
*   Investigate triggered alerts by examining the source IPs (`src`) and user agents (`user_agent`) associated with the failed authentication attempts in the logs.
*   Enforce multi-factor authentication (MFA) for all users to mitigate the risk of successful brute-force attacks.
*   Monitor for successful logins immediately following a burst of failed authentication attempts. Deploy the `Azure AD Successful Login After Failed Attempts` Sigma rule.
