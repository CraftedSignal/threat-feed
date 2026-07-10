---
title: AWS Account Brute-Force Detection
slug: 2024-01-aws-brute-force
description: This brief describes a detection for AWS accounts experiencing a high number of failed authentication attempts within a short timeframe, potentially indicating a brute-force attack targeting the account.
date: "2024-01-03T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - brute-force
  - credential-access
vendors:
  - Amazon
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1201
    technique_name: Password Cracking
references:
  - https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/IAM/password-policy.html
rules:
  - title: AWS High Number of Failed Console Logins
    description: Detects an AWS account experiencing more than 20 failed ConsoleLogin attempts within a 10-minute window, indicating potential brute-force activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1201
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Failed Console Login from Multiple IPs
    description: Detects failed ConsoleLogin events for a single user originating from multiple distinct IP addresses within a short timeframe, potentially indicating an attacker attempting to brute force credentials from different locations.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies potential brute-force attacks against AWS accounts by monitoring for a high number of failed authentication attempts. The detection focuses on identifying more than 20 failed `ConsoleLogin` events within a 5-minute window, as recorded in AWS CloudTrail logs. This activity is a strong indicator of malicious actors attempting to gain unauthorized access to an AWS environment. While the specific actors and their motivations remain unknown, the impact of a successful brute-force attack could include data breaches, resource hijacking, and further exploitation of the cloud infrastructure. Security teams should tune the threshold for failed attempts based on their organization's typical user behavior to minimize false positives.

## Attack Chain

1. **Initial Access Attempt:** The attacker initiates a brute-force attack targeting AWS accounts, attempting to guess usernames and passwords.
2. **ConsoleLogin Failure:** Each failed login attempt generates a `ConsoleLogin` event in AWS CloudTrail with an `action` value of "failure".
3. **Log Aggregation:** AWS CloudTrail logs are collected and ingested into a SIEM or security analytics platform.
4. **Event Correlation:** The SIEM aggregates `ConsoleLogin` failure events, grouping them by user account and timeframe.
5. **Threshold Breach:** The number of failed attempts for a given user within a 5-minute window exceeds a defined threshold (e.g., 20 attempts).
6. **Potential Account Compromise:** If the brute-force attack is successful, the attacker gains unauthorized access to the targeted AWS account.
7. **Privilege Escalation/Lateral Movement:** Once inside, the attacker may attempt to escalate privileges and move laterally to access sensitive resources.
8. **Data Exfiltration/Resource Exploitation:** The attacker may exfiltrate sensitive data, deploy malicious workloads, or otherwise exploit the compromised AWS environment.

## Impact

A successful brute-force attack can lead to significant damage, including unauthorized access to sensitive data, deployment of malicious resources (e.g., cryptocurrency miners), and disruption of critical services. The number of affected victims depends on the scope of the attacker's access within the compromised AWS environment. Specific sectors at risk include any organization relying on AWS for its infrastructure and data storage. The financial impact can be substantial, considering the potential for data breach fines, incident response costs, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to detect AWS accounts with a high number of failed login attempts, leveraging AWS CloudTrail logs (`logsource: category: cloudtrail, product: aws`).
*   Investigate triggered alerts to determine if the failed logins are legitimate or indicative of a brute-force attack, focusing on the source IPs and user agents involved.
*   Implement multi-factor authentication (MFA) for all AWS accounts to significantly reduce the risk of successful brute-force attacks.
*   Review and enforce strong password policies, as referenced in the provided Trend Micro article (`references: https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/IAM/password-policy.html`).
*   Tune the threshold in the provided Sigma rule based on your organization's baseline login behavior to reduce false positives.
