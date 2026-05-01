---
title: AWS KMS Key Policy Updated via PutKeyPolicy
slug: 2024-01-aws-kms-key-policy-put
description: Detection of successful PutKeyPolicy calls on AWS KMS keys to identify potential privilege escalation or unauthorized access by adversaries modifying key policies to decrypt or exfiltrate data.
date: "2024-01-22T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - kms
  - privilege-escalation
  - defense-evasion
vendors:
  - Amazon
products:
  - KMS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
  - https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
rules:
  - title: AWS KMS Key Policy Updated via PutKeyPolicy
    description: Detects successful PutKeyPolicy calls on AWS KMS keys, indicating potential privilege escalation or unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.005
      - T1562
    data_sources:
      - cloudtrail
      - aws
  - title: AWS KMS Key Policy Updated with External Principal
    description: Detects PutKeyPolicy calls that add an external AWS account as a principal with decrypt permissions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.005
      - T1562
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule detects the successful execution of the `PutKeyPolicy` API call within Amazon Web Services Key Management Service (AWS KMS). The `PutKeyPolicy` action replaces the entire key policy associated with a KMS key, potentially granting new or expanded permissions to principals. An adversary who gains the ability to modify KMS key policies (`kms:PutKeyPolicy`) can escalate privileges by adding external accounts or roles, allowing them to decrypt data protected by the key or maintain persistent access even after credential rotation. This activity is crucial to monitor, as it can lead to significant data breaches and unauthorized access to sensitive information. The rule focuses on identifying deviations from expected KMS key policy management practices to detect potentially malicious activity.

## Attack Chain

1.  An attacker compromises an AWS account or obtains IAM credentials with sufficient permissions, including `kms:PutKeyPolicy` on a target KMS key.
2.  The attacker uses the compromised credentials to call the `PutKeyPolicy` API, replacing the existing key policy with a modified version.
3.  The modified key policy grants the attacker's AWS account, or an external account, permissions to perform cryptographic operations on the key, such as `kms:Decrypt` or `kms:GenerateDataKey`.
4.  The attacker utilizes the newly granted permissions to decrypt data encrypted with the KMS key, such as data stored in S3 buckets or EBS volumes.
5.  The attacker may also grant administrative actions to new identities.
6.  The attacker exfiltrates the decrypted data to an external location.
7.  The attacker attempts to cover their tracks by deleting CloudTrail logs or modifying other security configurations.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data encrypted with the KMS key, potentially resulting in data breaches, financial loss, and reputational damage. The severity depends on the sensitivity of the data protected by the key and the scope of access granted to the attacker. This can impact organizations across various sectors that rely on AWS KMS for data encryption, potentially affecting millions of records and causing significant operational disruption.

## Recommendation

*   Deploy the Sigma rule "AWS KMS Key Policy Updated via PutKeyPolicy" to your SIEM and tune for your environment to detect unauthorized modifications to KMS key policies.
*   Review the policy document diff in `aws.cloudtrail.request_parameters` and `aws.cloudtrail.response_elements` to identify unauthorized changes to principals.
*   Restrict the `kms:PutKeyPolicy` permission to break-glass roles only, limiting the potential for unauthorized modifications.
*   Monitor `iam:AttachRolePolicy` and `sts:AssumeRole` events to correlate with potential privilege escalation attempts related to KMS key access.
*   Restore a known-good KMS policy from backup or IAM/KMS change history to remediate unauthorized modifications.
