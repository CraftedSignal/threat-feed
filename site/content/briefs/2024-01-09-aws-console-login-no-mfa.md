---
title: Successful AWS Console Login Without MFA
slug: 2024-01-09-aws-console-login-no-mfa
description: Successful AWS console logins without multi-factor authentication can indicate compromised credentials, misconfigured security settings, or unauthorized access attempts.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - mfa
  - initial-access
vendors:
  - Amazon
products:
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/iam-user-without-mfa/
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
rules:
  - title: AWS Console Login Without MFA - Expanded Detection
    description: Detects successful AWS console logins without MFA, including specific event names and expanding field coverage.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - aws
      - cloudtrail
  - title: AWS Console Login Failed Without MFA
    description: Detects failed AWS console logins without MFA, potentially indicating brute-force attempts.
    platform: sigma
    severity: low
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The absence of multi-factor authentication (MFA) during AWS console logins presents a significant security risk. Threat actors often target AWS environments due to the high value of data and services hosted within. An attacker gaining initial access through compromised credentials can move laterally, escalate privileges, and potentially exfiltrate sensitive data, deploy malicious workloads, or disrupt critical services. This activity can go unnoticed for extended periods, increasing the potential for damage. Detecting successful console logins without MFA is crucial for identifying potential breaches and ensuring the enforcement of security best practices. This brief focuses on detecting these logins to mitigate the risk of unauthorized access and potential data breaches.

## Attack Chain

1.  An attacker obtains valid AWS credentials, possibly through phishing, credential stuffing, or by exploiting a vulnerable service.
2.  The attacker uses the compromised credentials to attempt to log in to the AWS Management Console.
3.  The attacker successfully authenticates without providing an MFA code, indicating MFA is not enabled or is bypassed for the compromised user.
4.  After successful login, the attacker enumerates existing AWS resources, including EC2 instances, S3 buckets, and IAM roles, using the AWS CLI or Console.
5.  The attacker attempts to escalate privileges by exploiting IAM misconfigurations or vulnerabilities to gain access to more sensitive resources.
6.  The attacker modifies security configurations, such as disabling CloudTrail logging or creating new IAM users with elevated permissions, to establish persistence.
7.  The attacker accesses sensitive data stored in S3 buckets or databases, potentially exfiltrating it to an external location.

## Impact

A successful AWS console login without MFA can lead to a full compromise of the AWS environment. Attackers can gain unauthorized access to sensitive data, disrupt critical services, and deploy malicious workloads. The lack of MFA increases the likelihood of successful credential-based attacks, potentially affecting a large number of organizations hosting data and applications in AWS. Consequences include data breaches, financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the "AWS Successful Console Login Without MFA" Sigma rule to your SIEM to detect logins without MFA (rule).
*   Enforce MFA for all AWS IAM users, especially those with administrative privileges to prevent initial access (reference: https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/iam-user-without-mfa/).
*   Regularly audit IAM configurations to identify and remediate misconfigurations that could allow privilege escalation.
*   Monitor CloudTrail logs for suspicious activity following a console login, such as resource enumeration or IAM policy changes (logsource).
