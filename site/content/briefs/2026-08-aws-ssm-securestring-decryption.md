---
title: Detection of Potential Credential Access via AWS SSM SecureString Decryption
slug: 2026-08-aws-ssm-securestring-decryption
description: This detection monitors for the first occurrence of an AWS identity accessing AWS Systems Manager (SSM) SecureString parameters with the decryption flag enabled, indicating potential unauthorized retrieval of stored sensitive credentials.
date: "2026-08-24T09:45:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - cloud
  - aws
  - monitoring
vendors:
  - Amazon
products:
  - AWS Systems Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Adversaries may target SecureStrings to retrieve sensitive information such as encryption keys, passwords, and other credentials that are stored securely.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_retrieve_secure_string_parameters_via_ssm.toml
rules:
  - title: Detect AWS SSM SecureString Parameter Request with Decryption
    description: Detects the first occurrence of an AWS identity accessing SSM SecureString parameters with the decryption flag set to true via GetParameter or GetParameters API actions.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable CloudTrail Data Events for SSM API calls
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into GetParameter API usage
  mitigation_plan:
    - priority: short_term
      action: Review IAM policies for identities accessing SecureStrings
      owner: IAM Security
      addresses: T1555.006
      evidence: Principle of least privilege
---

Adversaries targeting AWS environments often seek to retrieve sensitive information, such as API keys, database passwords, and encryption keys, stored within the AWS Systems Manager (SSM) Parameter Store. SecureString parameters are encrypted at rest using AWS Key Management Service (KMS) keys. When an attacker gains initial access, they may attempt to leverage the `GetParameter` or `GetParameters` API actions with the `withDecryption` parameter set to `true` to obtain plaintext credentials. 

This detection logic monitors AWS CloudTrail management events to identify the first time an AWS identity requests the decryption of these sensitive parameters. By focusing on new occurrences of this behavior for specific identities, security teams can identify anomalous credential discovery attempts that deviate from established operational baselines. Monitoring these events is critical, as successful retrieval of these secrets often facilitates subsequent privilege escalation and lateral movement within the cloud infrastructure.

## Impact

Successful exploitation of this technique allows an attacker to bypass encryption controls and obtain plaintext credentials stored in AWS Parameter Store. This can lead to full compromise of downstream services, data exfiltration, or unauthorized persistence within the environment, depending on the scope of the accessed secrets.

## Recommendation

- Ensure AWS CloudTrail is configured to collect data events for AWS SSM API actions to provide the necessary visibility for this detection.
- Deploy the provided detection logic to identify the first-time access of SecureString parameters with decryption enabled, and investigate alerts for unauthorized identities.
- Review IAM policies and apply the principle of least privilege to restrict access to the `ssm:GetParameter` and `ssm:GetParameters` actions, specifically where `withDecryption` is required.
- Audit IAM roles and users that have permissions to both SSM Parameter Store and the associated KMS keys used for encryption.
