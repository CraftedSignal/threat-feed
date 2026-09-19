---
title: AWS S3 Bucket MFA Delete Disablement
slug: 2026-09-aws-s3-mfa-delete-disabled
description: Adversaries may disable MFA Delete on versioned Amazon S3 buckets to enable the permanent destruction of object version history, a critical step in ransomware attacks targeting cloud-native backups.
date: "2026-09-07T13:29:32Z"
lastmod: "2026-09-19T13:27:08Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Amazon
products:
  - AWS S3
  - S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Disabling MFA Delete removes this safeguard and is a recognized ransomware preparation step.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_s3_mfa_delete_disabled.toml
rules:
  - title: Detect AWS S3 Bucket MFA Delete Disabled
    description: Detects PutBucketVersioning API calls that disable the MFA Delete feature, indicating a potential ransomware preparation step.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
  immediate_actions:
    - action: Deploy the detection rule for MFA Delete disablement.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID b8654454-2757-41b4-ae1a-69b3be704c28
  mitigation_plan:
    - priority: immediate
      action: Enable MFA Delete on all critical S3 buckets containing versioned data.
      owner: Cloud Security Team
      addresses: T1490
      evidence: Source documentation for Multi-Factor Authentication Delete
updates:
  - at: "2026-09-19T13:27:08Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_s3_mfa_delete_disabled.toml
---

Disabling MFA Delete on an Amazon S3 bucket removes a mandatory security control that requires multi-factor authentication to permanently delete object versions or change versioning status. This capability is specifically designed to prevent the unauthorized destruction of data backups. Adversaries who have compromised long-term access keys or gained administrative control over an S3 environment can use the PutBucketVersioning API call to set the MfaDelete parameter to Disabled. By neutralizing this safeguard, attackers gain the ability to permanently delete previous object versions, effectively destroying the organization's ability to recover from ransomware encryption. Because only the AWS root user can modify MFA Delete settings, the occurrence of this API call is a high-confidence indicator of root credential compromise or unauthorized escalation of privileges.

## Attack Chain

1. Attacker gains initial access to the cloud environment, typically via compromised long-term access keys or session tokens.
2. Attacker performs reconnaissance to identify sensitive S3 buckets that contain backups or critical data.
3. Attacker uses compromised credentials to assume an IAM role or directly access the root account to gain necessary permissions.
4. Attacker monitors S3 configuration and identifies buckets with MFA Delete enabled as a recovery barrier.
5. Attacker executes the PutBucketVersioning API call, setting MfaDelete to Disabled to weaken bucket security.
6. Attacker deletes existing object versions or executes ransomware encryption on current files to ensure no recovery point exists.

## Impact

Successful exploitation allows attackers to destroy data versioning history within Amazon S3 buckets. This eliminates the capability to restore files from versioned backups after a ransomware attack, significantly increasing the probability of data loss and the likelihood that victims will be forced to pay extortion demands to restore operational continuity.

## Recommendation

* Deploy the provided Sigma detection rule to alert on successful PutBucketVersioning API calls where MfaDelete is set to Disabled.
* Restrict the use of AWS root user credentials to strictly defined break-glass scenarios and implement hardware-based MFA for these accounts.
* Use AWS CloudTrail and IAM Access Analyzer to audit and restrict principals authorized to invoke the PutBucketVersioning API.
* Enable AWS Config rules to monitor and automatically remediate configurations where bucket versioning or MFA Delete settings are altered.
