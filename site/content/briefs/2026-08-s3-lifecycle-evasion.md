---
title: Abuse of S3 Bucket Lifecycle Expiration for Defense Evasion
slug: 2026-08-s3-lifecycle-evasion
description: Adversaries can abuse Amazon S3 lifecycle expiration configurations to automate the deletion of logs and forensic evidence, hindering incident investigation and response.
date: "2026-08-24T09:46:24Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - defense-evasion
  - cloud-security
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries can abuse them by configuring auto-deletion of logs, forensic evidence, or sensitive objects to cover their tracks.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.008
    technique_name: Disable or Modify Cloud Logs
    evidence: Adversaries can abuse them by configuring auto-deletion of logs, forensic evidence, or sensitive objects to cover their tracks.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485.001
    technique_name: Lifecycle-Triggered Deletion
    evidence: Adversaries can abuse them by configuring auto-deletion of logs, forensic evidence, or sensitive objects to cover their tracks.
    confidence_band: high
rules:
  - title: AWS S3 Bucket Expiration Lifecycle Configuration Added
    description: Detects the addition of an expiration lifecycle configuration to an Amazon S3 bucket, which can be used to automate the deletion of logs or forensic evidence.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for suspicious PutBucketLifecycle events.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided logic for detecting this TTP via CloudTrail.
  mitigation_plan:
    - priority: medium_term
      action: Enable S3 Object Lock on buckets containing security-critical logs.
      owner: IT Operations
      addresses: Prevention of unauthorized log deletion via lifecycle rules.
      evidence: Recommended in the investigation guide provided in the source.
---

Adversaries with sufficient IAM permissions in an AWS environment can modify Amazon S3 bucket lifecycle configurations to automate the deletion of stored objects. By invoking the `PutBucketLifecycle` or `PutBucketLifecycleConfiguration` APIs, an attacker can set an expiration policy that deletes logs, forensic artifacts, or sensitive data after a defined period. This technique is used to maintain operational secrecy and prevent detection teams from performing effective post-incident analysis. This activity is often silent and can be difficult to detect if monitoring focuses only on explicit `DeleteObject` calls rather than configuration management events. Security teams should monitor CloudTrail logs for unexpected lifecycle changes, particularly on buckets containing security-critical data, and validate these changes against known infrastructure-as-code deployments.

## Impact

Successful abuse of S3 lifecycle policies leads to the permanent loss of logs and forensic evidence, significantly complicating incident response efforts. This technique directly targets the availability of data needed for auditing and attribution in cloud environments.

## Recommendation

* Deploy detection logic to monitor CloudTrail for `PutBucketLifecycle` and `PutBucketLifecycleConfiguration` API calls.
* Establish guardrails using AWS Config rules, such as `s3-bucket-lifecycle-configuration-check`, to monitor and alert on unauthorized lifecycle changes.
* Restrict `s3:PutLifecycleConfiguration` and `s3:PutBucketLifecycle` IAM permissions to specific, highly privileged administrative roles.
* Enable S3 Object Lock on buckets containing critical audit logs or forensic evidence to prevent deletion, even if lifecycle rules are modified.
