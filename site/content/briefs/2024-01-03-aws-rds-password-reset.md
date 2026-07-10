---
title: AWS RDS Master User Password Reset Detection
slug: 2024-01-03-aws-rds-password-reset
description: Detection of unauthorized master user password resets for Amazon RDS DB instances via AWS CloudTrail logs, potentially leading to sensitive data access and data breaches.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - credential-access
  - rds
vendors:
  - AWS
products:
  - Amazon RDS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://aws.amazon.com/premiumsupport/knowledge-center/reset-master-user-password-rds
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_credential_access_rds_password_reset.yml
rules:
  - title: AWS RDS Master User Password Reset
    description: Detects when the master user password for an Amazon RDS DB instance is reset via the AWS API. This may indicate credential compromise or other unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - cloudtrail
      - aws
  - title: AWS RDS DBCluster Master User Password Reset
    description: Detects when the master user password for an Amazon RDS DBCluster is reset via the AWS API. This may indicate credential compromise or other unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic detects the resetting of the master user password for an Amazon RDS DB instance. The detection leverages AWS CloudTrail logs ingested via Amazon Security Lake to identify events where the `ModifyDBInstance` or `ModifyDBCluster` API calls include a new `masterUserPassword` parameter. This activity is significant because unauthorized password resets can grant attackers access to sensitive data stored in production databases, which may contain sensitive information such as credit card numbers, PII, or protected health information. If the password reset is confirmed to be malicious, it could lead to data breaches, regulatory non-compliance, and significant reputational damage. This detection is based on version 8 of the Splunk Security Content analytic "ASL AWS Credential Access RDS Password reset" published on April 15, 2026.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials (T1110) or phishing (T1586.003).
2.  The attacker leverages the AWS Management Console or AWS CLI to interact with the RDS service.
3.  The attacker issues a `ModifyDBInstance` or `ModifyDBCluster` API call.
4.  Within the `ModifyDBInstance` or `ModifyDBCluster` API call, the attacker includes the `masterUserPassword` parameter.
5.  The RDS service processes the request and resets the master user password for the specified database instance or cluster.
6.  The attacker uses the newly reset master user password to authenticate to the RDS database instance.
7.  The attacker gains access to sensitive data stored within the RDS database.
8.  The attacker exfiltrates or manipulates the data for malicious purposes.

## Impact

A successful attack resulting in unauthorized password reset can lead to a complete compromise of the RDS database instance. This could result in data breaches with millions of records exposed, regulatory fines for non-compliance (e.g., GDPR, HIPAA), and severe reputational damage affecting customer trust and stock prices. Sectors heavily reliant on RDS databases, such as finance, healthcare, and e-commerce, are particularly vulnerable.

## Recommendation

*   Deploy the Sigma rule `AWS RDS Master User Password Reset` to your SIEM and tune for your environment using AWS CloudTrail logs ingested via Amazon Security Lake.
*   Investigate any detected instances of `ModifyDBInstance` or `ModifyDBCluster` API calls containing the `masterUserPassword` parameter by pivoting to the originating IP address (`src_endpoint.ip`) and user agent (`http_request.user_agent`) from the Sigma rule.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with permissions to manage RDS instances, to mitigate compromised credential attacks (T1110).
*   Review and enforce the principle of least privilege for IAM roles, ensuring that users only have the necessary permissions to perform their job functions.
*   Monitor AWS CloudTrail logs for other suspicious API calls related to RDS, such as modifications to security groups or network ACLs.
