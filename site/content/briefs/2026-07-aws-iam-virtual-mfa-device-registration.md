---
title: AWS IAM Virtual MFA Device Registration Attempt with Session Token
slug: 2026-07-aws-iam-virtual-mfa-device-registration
description: Adversaries are exploiting compromised temporary AWS session credentials (access keys starting with 'ASIA') to register or enable virtual MFA devices, establishing persistence and maintaining access to high-privilege accounts even after credential rotation or password resets.
date: "2026-07-15T14:14:33Z"
lastmod: "2026-07-20T13:11:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - identity-and-access-audit
vendors:
  - AWS
  - Amazon Web Services
products:
  - IAM
  - CloudTrail
  - AWS IAM
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries who compromise temporary credentials may abuse this behavior to establish persistence by attaching new MFA devices to maintain access to high-privilege accounts despite key rotation or password resets.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Detects attempts to create or enable a Virtual MFA device (CreateVirtualMFADevice, EnableMFADevice) using temporary AWS credentials (access keys beginning with ASIA). Session credentials are short-lived and tied to existing authenticated sessions, so using them to register or enable MFA devices is unusual. Adversaries who compromise temporary credentials may abuse this behavior to establish persistence by attaching new MFA devices.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries who compromise temporary credentials may abuse this behavior to establish persistence by attaching new MFA devices to maintain access to high-privilege accounts despite key rotation or password resets.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_aws_attempt_to_register_virtual_mfa_device.toml
  - https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_user_created_access_keys_for_another_user.toml
rules:
  - title: AWS IAM Virtual MFA Device Registration Attempt with Session Token
    description: Detects attempts to create or enable a Virtual MFA device (CreateVirtualMFADevice, EnableMFADevice) using temporary AWS credentials (access keys beginning with ASIA) outside of console login sessions, indicating a potential persistence mechanism.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078
      - T1078.004
      - T1098
      - T1098.005
      - T1556
      - T1556.006
    data_sources:
      - cloud
      - aws
rules_count: 1
updates:
  - at: "2026-07-20T13:11:18Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_aws_attempt_to_register_virtual_mfa_device.toml
---

Adversaries are leveraging compromised temporary AWS session credentials, identifiable by access keys prefixed with "ASIA", to create or enable virtual Multi-Factor Authentication (MFA) devices within AWS Identity and Access Management (IAM). These temporary credentials, typically short-lived and tied to existing authenticated sessions, are not ordinarily used for modifying core IAM authentication mechanisms. By exploiting this unusual behavior, attackers can establish a persistent backdoor to privileged AWS accounts. This technique allows them to maintain unauthorized access even if the primary credentials (passwords, long-term access keys) are rotated or reset, effectively bypassing standard security measures. The activity is observed as `CreateVirtualMFADevice` or `EnableMFADevice` API calls originating from non-console sessions with "ASIA" prefixed access keys, indicating an attacker-controlled, non-legitimate session token usage for persistence. This method has been observed in real-world incidents, such as the Bybit hack.

## Attack Chain

1. **Initial Access**: An adversary gains initial unauthorized access to an AWS environment, often through compromised IAM user credentials, assumed role credentials, or other means.
2. **Credential Acquisition**: The adversary acquires temporary AWS session credentials (access keys starting with "ASIA") from the compromised environment. These might be obtained from exposed API keys, EC2 instance metadata, or via other AWS Security Token Service (STS) calls like `AssumeRole` or `GetSessionToken`.
3. **MFA Device Creation Attempt**: Using the compromised temporary credentials, the adversary invokes the `CreateVirtualMFADevice` API call to create a new virtual MFA device.
4. **MFA Device Enablement Attempt**: Subsequently, the adversary invokes the `EnableMFADevice` API call to bind this newly created virtual MFA device to a high-privilege IAM user or role.
5. **Persistence Establishment**: Upon successful creation and enablement of the virtual MFA device, the adversary has established a new, attacker-controlled MFA device on a privileged account.
6. **Maintain Access**: The adversary can now use this newly attached MFA device to authenticate and maintain persistent access to the compromised AWS account, circumventing any attempts to rotate passwords or long-term access keys for the affected principal.

## Impact

Successful exploitation of this technique grants adversaries persistent, unauthorized access to privileged AWS accounts, allowing them to bypass crucial security controls like MFA and credential rotation. The primary impact is the loss of control over the compromised AWS environment, leading to potential data exfiltration, resource manipulation, service disruption, or further lateral movement. This can affect any AWS customer with compromised temporary credentials, with high-privilege accounts being the primary target for persistence. Specific victim counts or targeted sectors are not detailed in the source, but the Bybit hack referenced indicates financial sector impact. The adversary's ability to retain access even after legitimate credentials are changed significantly prolongs incident response and recovery efforts.

## Recommendation

* Deploy the `AWS IAM Virtual MFA Device Registration Attempt with Session Token` Sigma rule to your SIEM to detect this activity.
* Investigate all alerts generated by the `AWS IAM Virtual MFA Device Registration Attempt with Session Token` rule, focusing on the `aws.cloudtrail.user_identity.arn`, `aws.cloudtrail.user_identity.access_key_id`, `user_agent.original`, `source.ip`, and `cloud.region` fields.
* If anomalous activity is confirmed, immediately revoke or expire the temporary credentials involved (if applicable, via `aws sts revoke-session`).
* Disable or delete any newly created virtual MFA devices via `DeleteVirtualMFADevice` if they are unauthorized.
* Rotate passwords and long-term access keys for any IAM users associated with the compromised temporary credentials.
* Enforce strict IAM policies, limiting `iam:EnableMFADevice` and `iam:CreateVirtualMFADevice` permissions to only trusted administrative roles.
* Implement `aws:MultiFactorAuthPresent` conditions in IAM policies to enforce MFA usage for sensitive actions.
* Enable AWS CloudTrail logging for all management events across all regions to ensure visibility into IAM activities.
