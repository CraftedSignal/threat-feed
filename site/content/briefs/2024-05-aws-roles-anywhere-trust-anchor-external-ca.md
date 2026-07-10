---
title: AWS IAM Roles Anywhere Trust Anchor Created with External CA
slug: 2024-05-aws-roles-anywhere-trust-anchor-external-ca
description: The creation of an AWS IAM Roles Anywhere Trust Anchor using an external Certificate Authority (CA) instead of an AWS-managed CA allows adversaries to establish persistent access by using their own CA to sign certificates for authentication.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - rolesanywhere
  - persistence
vendors:
  - AWS
products:
  - IAM Roles Anywhere
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
  - https://ermetic.com/blog/aws/keep-your-iam-users-close-keep-your-third-parties-even-closer-part-1/
  - https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_CreateTrustAnchor.html
rules:
  - title: AWS IAM Roles Anywhere Trust Anchor Created with External CA
    description: Detects the creation of an AWS IAM Roles Anywhere Trust Anchor that uses an external certificate authority (CA) rather than an AWS-managed ACM PCA.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM RolesAnywhere AssumeRoleWithCertificate from Untrusted Anchor
    description: Detects attempts to assume an IAM role using a certificate associated with a trust anchor that is not managed by AWS ACM PCA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1556
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

AWS IAM Roles Anywhere allows workloads outside AWS to assume IAM roles by presenting X.509 certificates. A trust anchor defines which certificate authority (CA) AWS trusts to validate these external identities. This rule detects when a trust anchor is created using an external CA (`sourceType= "CERTIFICATE_BUNDLE" or "SELF_SIGNED_REPOSITORY"`) rather than an ACM-managed CA (`sourceType="AWS_ACM_PCA"`). An adversary establishing persistent external access can exploit this by authenticating using certificates signed by their own CA, even after key rotation. This activity is logged by CloudTrail, and this rule focuses on detecting the `CreateTrustAnchor` event with a non-AWS CA source type, potentially indicating unauthorized federation attempts.

## Attack Chain

1. The attacker gains initial access to an AWS account with sufficient privileges to manage IAM Roles Anywhere.
2. The attacker uses the `CreateTrustAnchor` API to register an external CA as a trusted root for Roles Anywhere. This involves setting the `sourceType` to `CERTIFICATE_BUNDLE` or `SELF_SIGNED_REPOSITORY` instead of `AWS_ACM_PCA`.
3. The attacker creates an IAM Roles Anywhere profile, associating it with the newly created trust anchor and one or more IAM roles.
4. The attacker generates a client certificate signed by their external CA.
5. The attacker uses the `AssumeRoleWithCertificate` API call, presenting the client certificate to assume the associated IAM role.
6. The attacker can now perform actions within the AWS environment with the privileges of the assumed IAM role.
7. The attacker maintains persistent access even after standard credential rotation by generating new certificates signed by their trusted CA.
8. The final objective is often to maintain long-term access to AWS resources, potentially for data exfiltration, lateral movement, or other malicious activities.

## Impact

Successful exploitation allows attackers to establish persistent access to AWS environments from outside the AWS infrastructure. This can lead to unauthorized access to sensitive data, lateral movement within the AWS environment, and potentially complete compromise of the AWS account. This scenario can bypass standard AWS security controls and makes credential rotation ineffective. The number of victims is currently unknown, but any organization using AWS IAM Roles Anywhere is potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule "AWS IAM Roles Anywhere Trust Anchor Created with External CA" to your SIEM to detect unauthorized trust anchor creations (rule).
*   Monitor AWS CloudTrail logs for `CreateTrustAnchor` events and validate the `sourceType` to ensure only authorized CAs are used (log source).
*   Restrict `rolesanywhere:CreateTrustAnchor` permissions to only authorized security administrators (reference).
*   Implement AWS Config rules or Security Hub findings to detect anomalous IAM and Roles Anywhere behavior (reference).
*   Regularly review existing trust anchors and profiles in IAM Roles Anywhere to identify and remove any unauthorized configurations (reference).
