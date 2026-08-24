---
title: Abuse of AWS IAM CreateAccessKey API for Persistence
slug: 2026-08-aws-iam-createaccesskey
description: Adversaries with compromised credentials may abuse the AWS IAM CreateAccessKey API to establish persistence or escalate privileges by generating new programmatic keys for other IAM users.
date: "2026-08-24T09:50:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - privilege-escalation
  - iam
vendors:
  - Amazon
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary with access to a set of compromised credentials may attempt to persist or escalate privileges by creating a new set of credentials for an existing user.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary with access to a set of compromised credentials may attempt to persist or escalate privileges by creating a new set of credentials for an existing user.
    confidence_band: high
references:
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/#iamcreateaccesskey
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-iam-persistence
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review all IAM policies granting iam:CreateAccessKey to identify over-privileged non-admin users.
      owner: SOC
      due: 48h
      evidence: Source provides guidance on restricting risky principals.
  enrichment_needed:
    - item: Cross-reference newly created access keys with CloudTrail logs for subsequent usage from anomalous IPs.
      owner: CTI
      reason: Identify if the created key is already being used maliciously.
      evidence: Source documentation on incident response flow.
  mitigation_plan:
    - priority: short_term
      action: Enable multi-region CloudTrail logging and GuardDuty to capture all IAM activity.
      owner: IT Operations
      addresses: General account persistence
      evidence: Source recommends enabling security services.
---

Adversaries possessing compromised AWS credentials can perform account manipulation to ensure long-term access or elevate their privileges. By invoking the `iam:CreateAccessKey` API operation, an attacker can generate a new set of programmatic access keys for a different IAM user identity. This activity, when performed by an unauthorized principal, is a common tactic used by threat actors to establish persistence in a cloud environment. While legitimate credential rotation by administrators or automated systems involves this API call, malicious use is often identifiable by discrepancies between the calling IAM identity and the target user. This threat is particularly relevant to environments where IAM policies are overly permissive, allowing non-administrative users to manage keys for other accounts. Defenders must distinguish between sanctioned automated workflows and unauthorized manual key creation to effectively mitigate the risk of credential-based persistence.

## Attack Chain

1. Attacker obtains valid AWS IAM credentials via phishing, exposed environment variables, or other initial access vectors.
2. Attacker performs reconnaissance to identify high-value or elevated-privilege IAM users within the target AWS account.
3. Attacker invokes the `iam:CreateAccessKey` API operation targeting a secondary user account.
4. AWS IAM validates that the calling user possesses the required permissions to create keys for the target.
5. The API call succeeds, and AWS generates a new `accessKeyId` and `secretAccessKey` for the target user.
6. Attacker exfiltrates the newly created programmatic credentials for long-term use.
7. Attacker uses the new credentials to perform unauthorized API actions, access sensitive S3 buckets, or further move laterally across the infrastructure.
8. Attacker maintains persistent access even if their original compromised credentials are rotated or revoked.

## Impact

Successful abuse of the `CreateAccessKey` API allows adversaries to maintain persistent, long-term access to AWS environments, bypassing initial credential revocation. This can result in unauthorized data exfiltration, lateral movement to other AWS services, and full account compromise. The impact is significant for organizations relying on cloud-based infrastructure, as unauthorized key creation often remains undetected in noisy environments, potentially leading to widespread data exposure and operational disruption.

## Recommendation

- Implement least-privilege IAM policies to restrict `iam:CreateAccessKey` permissions to only authorized administrative roles or specific automation principals.
- Deploy detection rules to alert on `CreateAccessKey` events where the calling `userIdentity.arn` does not match the target `userName`.
- Perform regular audits of IAM access keys to identify and disable any keys that were created outside of established CI/CD or rotation pipelines.
- Integrate CloudTrail, GuardDuty, and AWS Security Hub to monitor for anomalous API activity and suspicious usage patterns from newly created credentials.
- Enforce Multi-Factor Authentication (MFA) for all IAM users to increase the difficulty of unauthorized credential usage following the creation of programmatic access keys.
