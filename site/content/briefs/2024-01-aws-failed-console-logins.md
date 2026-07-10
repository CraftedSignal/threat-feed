---
title: AWS High Number of Failed Console Login Attempts
slug: 2024-01-aws-failed-console-logins
description: An IP address exhibiting more than 20 failed AWS console login attempts within a 5-minute window, indicative of potential brute-force or password spraying attacks against AWS accounts.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - brute-force
  - password-spraying
  - credential-access
vendors:
  - AWS
products:
  - AWS
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
  - https://attack.mitre.org/techniques/T1110/003/
  - https://www.whiteoaksecurity.com/blog/goawsconsolespray-password-spraying-tool/
  - https://softwaresecuritydotblog.wordpress.com/2019/09/28/how-to-protect-against-credential-stuffing-on-aws/
rules:
  - title: AWS High Number Of Failed Console Logins
    description: Detects an IP address with a high number of failed AWS console login attempts within a short timeframe, indicating potential brute-force or password spraying.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
      - T1110.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Failed Console Login with Specific User Agent
    description: Detects failed AWS console logins with a specific user agent, potentially indicating automated tools.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic identifies potential brute-force or password spraying attacks against AWS accounts. It focuses on detecting a high volume of failed console login attempts originating from a single IP address within a short timeframe. Specifically, it triggers when an IP exhibits 20 or more failed login attempts within a 5-minute window, as recorded in AWS CloudTrail logs. The activity is based on the eventName `ConsoleLogin` with a failure action. Successful exploitation could lead to unauthorized access to AWS resources, data breaches, and further malicious activity within the AWS environment. The detection is designed to identify and alert on suspicious authentication patterns that bypass normal security measures and represent a significant risk to AWS account security.

## Attack Chain

1.  **Initial Access:** The attacker attempts to gain initial access to the AWS environment by targeting the AWS Management Console login page.
2.  **Credential Guessing:** The attacker initiates a password spraying or brute-force attack, attempting to authenticate with multiple usernames and passwords from a single IP address (T1110.003, T1110.004).
3.  **CloudTrail Logging:** AWS CloudTrail logs each failed `ConsoleLogin` attempt, capturing the source IP address (`src`), username (`user_name`), and timestamp.
4.  **Log Aggregation:** The security monitoring system collects and aggregates the CloudTrail logs.
5.  **Threshold Breach:** The system identifies an IP address that exceeds the defined threshold of 20 failed login attempts within a 5-minute window.
6.  **Alert Trigger:** An alert is generated, indicating a potential brute-force or password spraying attack.
7.  **Account Compromise (Potential):** If the attacker successfully guesses valid credentials, they gain unauthorized access to the AWS account.
8.  **Lateral Movement/Data Exfiltration (Potential):** Once inside the AWS environment, the attacker could potentially move laterally to access other resources or exfiltrate sensitive data.

## Impact

A successful brute-force or password spraying attack can lead to complete compromise of the AWS account. This can result in unauthorized access to sensitive data, modification or deletion of critical resources, and financial losses due to resource abuse. The number of affected users and the extent of the damage will depend on the attacker's skill and the permissions associated with the compromised account. This type of attack may lead to compliance violations and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune the `failed_attempts` threshold and `span` duration based on your environment's baseline login activity.
*   Investigate any triggered alerts by examining the source IP address (`src`) in the CloudTrail logs and correlate with other network activity.
*   Enforce multi-factor authentication (MFA) on all AWS accounts to mitigate the risk of credential-based attacks.
*   Monitor CloudTrail logs for other suspicious activities originating from the identified IP address.
*   Implement account lockout policies to automatically disable accounts after a certain number of failed login attempts.
