---
title: AWS IAM Long-Term Access Key Correlated with Elevated Detection Alerts
slug: 2026-06-aws-iam-access-key-correlation
description: This rule correlates AWS Long-Term Access Key First Seen from Source IP alerts with other open alerts of medium or higher severity that share the same IAM access key ID to prioritize investigation of potentially compromised accounts, helping identify post-compromise activity.
date: "2026-04-06T14:37:37Z"
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

This detection rule, published by Elastic, is designed to correlate AWS security alerts and prioritize investigations related to potentially compromised IAM access keys. Specifically, it focuses on scenarios where a long-term IAM access key is observed originating from a new source IP address (detected by the "AWS Long-Term Access Key First Seen from Source IP" rule, rule ID 9f8e3c5e-f72e-4e91-93f6-e98a4fae3e4f) and is also associated with other open alerts of medium, high, or critical…
