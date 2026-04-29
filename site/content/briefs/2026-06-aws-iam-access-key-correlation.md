---
title: AWS IAM Long-Term Access Key Correlated with Elevated Detection Alerts
slug: 2026-06-aws-iam-access-key-correlation
description: This rule correlates AWS Long-Term Access Key First Seen from Source IP alerts with other open alerts of medium or higher severity that share the same IAM access key ID to prioritize investigation of potentially compromised accounts, helping identify post-compromise activity.
date: "2026-04-06T14:37:37Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cloud
  - aws
  - iam
  - credential-access
  - initial-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1078/004/
rules:
  - title: AWS IAM User Agent from New IP Address
    description: Detects unusual user agent strings used with AWS IAM from previously unseen IPs, indicating potential account compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078
      - T1552
    data_sources:
      - network_connection
      - aws
  - title: AWS Unauthorized API Call with IAM Access Key
    description: Detects unauthorized AWS API calls made using an IAM access key, indicating potential credential compromise or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078
      - T1552
    data_sources:
      - network_connection
      - aws
rules_count: 2
---

This detection rule, published by Elastic, is designed to correlate AWS security alerts and prioritize investigations related to potentially compromised IAM access keys. Specifically, it focuses on scenarios where a long-term IAM access key is observed originating from a new source IP address (detected by the "AWS Long-Term Access Key First Seen from Source IP" rule, rule ID 9f8e3c5e-f72e-4e91-93f6-e98a4fae3e4f) and is also associated with other open alerts of medium, high, or critical severity. This correlation aims to surface instances where a newly exposed or compromised access key is actively being used for malicious activities, enabling security teams to respond more effectively to potential credential access incidents and initial access attempts. The rule is a higher-order rule that analyzes existing security alerts within an Elastic Security deployment and leverages the `kibana.alert` fields to identify related events.

## Attack Chain

1.  An attacker gains access to a valid AWS IAM Long-Term Access Key. This could be through phishing, credential stuffing, or exposed credentials in source code.
2.  The attacker uses the compromised access key to interact with AWS services from a new and previously unseen IP address. This triggers the "AWS Long-Term Access Key First Seen from Source IP" rule (rule ID: 9f8e3c5e-f72e-4e91-93f6-e98a4fae3e4f).
3.  The attacker leverages the compromised credentials to perform reconnaissance activities within the AWS environment, such as listing resources or querying IAM configurations.
4.  The attacker attempts to escalate privileges by exploiting misconfigurations or vulnerabilities in IAM policies.
5.  The attacker performs actions indicating lateral movement within the AWS environment, such as accessing or modifying resources in different AWS accounts.
6.  The attacker compromises additional AWS resources or services, such as EC2 instances or S3 buckets. These activities trigger medium, high, or critical severity alerts.
7.  The correlation rule identifies the co-occurrence of the "AWS Long-Term Access Key First Seen from Source IP" alert and other elevated severity alerts associated with the same access key ID.
8.  The security team investigates the correlated alerts and takes appropriate remediation steps, such as rotating the compromised access key and reviewing IAM policies.

## Impact

A successful attack leveraging compromised AWS IAM credentials can lead to significant data breaches, service disruption, and financial losses. Attackers can gain unauthorized access to sensitive data stored in S3 buckets, compromise EC2 instances, and disrupt critical AWS services. The correlation rule aims to reduce the dwell time of attackers by prioritizing the investigation of compromised credentials associated with ongoing malicious activity. This can prevent attackers from further escalating their attacks and minimizing the overall impact of the breach. Failure to detect and respond to these attacks can result in regulatory fines, reputational damage, and loss of customer trust.

## Recommendation

*   Deploy the "AWS IAM Long-Term Access Key Correlated with Elevated Detection Alerts" rule (rule ID 98cfaa44-83f0-4aba-90c4-363fb9d51a75) in your Elastic Security environment to identify potentially compromised IAM access keys.
*   Investigate alerts triggered by the rule by pivoting on the `aws.cloudtrail.user_identity.access_key_id` in CloudTrail and IAM to understand the context of the access key usage.
*   Review the sibling alerts identified by the rule using `Esql.kibana_alert_rule_name_values` and `Esql.kibana_alert_rule_id_values` to understand the scope and impact of the potential compromise.
*   Configure your Elastic Security deployment to properly map risk scores to severity levels, ensuring that `kibana.alert.risk_score >= 47` corresponds to medium or higher severity alerts.
*   Rotate or disable any IAM access keys identified as compromised by the rule to prevent further unauthorized access.
*   Enable AWS CloudTrail logging to capture detailed information about API calls made within your AWS environment, providing valuable context for investigating security alerts.
*   Implement the "AWS Long-Term Access Key First Seen from Source IP" rule (rule_id: 9f8e3c5e-f72e-4e91-93f6-e98a4fae3e4f) if not already enabled, as it is a pre-requisite for this correlation rule.
