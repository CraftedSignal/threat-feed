---
title: Abuse of AWS IAM Roles Anywhere via External Trust Anchors
slug: 2026-09-aws-iam-roles-anywhere-external-ca
description: Adversaries can establish persistent access to AWS environments by creating an IAM Roles Anywhere Trust Anchor using an unauthorized external Certificate Authority (CA) to sign forged client certificates.
date: "2026-09-18T19:40:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - persistence
  - iam
vendors:
  - Amazon
products:
  - AWS IAM Roles Anywhere
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries can exploit this feature by registering their own external CA as a trusted root.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Registering a rogue CA as a trusted root allows attackers to generate valid client certificates that persistently authenticate to AWS roles.
    confidence_band: high
rules:
  - title: Detect AWS IAM Roles Anywhere Trust Anchor Creation with External CA
    description: Detects the creation of an AWS IAM Roles Anywhere Trust Anchor using an external certificate authority (CA) instead of the AWS-managed Certificate Manager Private CA (ACM PCA).
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556
    data_sources:
      - process_creation
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for CreateTrustAnchor with external CA
      owner: Detection Engineering
      due: 24h
      evidence: Detection rule defined in brief
    - action: Audit IAM Roles Anywhere Trust Anchors in use
      owner: SOC
      due: 48h
      evidence: Recommendation to audit PKI trust chain
  mitigation_plan:
    - priority: immediate
      action: Restrict rolesanywhere:CreateTrustAnchor to security administrators
      owner: IT Operations
      addresses: Persistence via unauthorized Trust Anchors
      evidence: Recommendation section
---

AWS IAM Roles Anywhere enables workloads outside of AWS to assume IAM roles by presenting X.509 certificates validated against a registered Trust Anchor. While designed to simplify hybrid cloud identity, it introduces a persistence vector if misconfigured. Attackers with sufficient permissions can register a rogue external Certificate Authority (CA) as a Trust Anchor by configuring `sourceType` as `CERTIFICATE_BUNDLE` or `SELF_SIGNED_REPOSITORY` instead of the AWS-managed `AWS_ACM_PCA`. Once established, the adversary can generate arbitrary client certificates signed by this rogue CA. These certificates allow the attacker to programmatically authenticate as sensitive IAM roles from any location, effectively bypassing AWS-native certificate lifecycle management and maintaining long-term access that survives credential rotation and standard revocation processes.

## Impact

Successful exploitation allows for long-term, stealthy persistence within an AWS account. Attackers can assume highly privileged roles to exfiltrate data, modify cloud infrastructure, or escalate privileges further. Because the authentication is tied to a rogue CA controlled by the adversary, standard AWS-based revocation of temporary credentials or rotating service account keys will not invalidate the underlying access path until the Trust Anchor itself is deleted.

## Recommendation

- Deploy the provided Sigma rule to detect the creation of any IAM Roles Anywhere Trust Anchor that does not utilize the AWS ACM Private CA.
- Restrict the `rolesanywhere:CreateTrustAnchor` IAM permission to a strictly limited set of security administrators.
- Audit existing Trust Anchors to ensure all registered CAs belong to approved, organizationally managed PKI infrastructure.
- Utilize AWS Config or Security Hub to monitor and alert on new Trust Anchor creations and changes in their configuration.
