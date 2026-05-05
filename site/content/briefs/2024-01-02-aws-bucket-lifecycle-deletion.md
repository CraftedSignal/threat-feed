---
title: AWS S3 Bucket Lifecycle Rule for Rapid Log Deletion
slug: 2024-01-02-aws-bucket-lifecycle-deletion
description: An attacker modifies an AWS S3 bucket lifecycle policy to rapidly expire CloudTrail logs, hindering incident response and forensic analysis.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - aws
  - cloudtrail
  - defense_evasion
  - s3
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Amazon Security Lake
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/
  - https://splunkbase.splunk.com/app/1876
rules:
  - title: Detect AWS S3 Bucket Lifecycle Policy Modification for Rapid Deletion
    description: Detects modification of an AWS S3 bucket lifecycle policy to enable rapid deletion of logs, potentially to evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1485.001
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS S3 Bucket Lifecycle Policy Modification using ASL
    description: Detects modification of an AWS S3 bucket lifecycle policy using Amazon Security Lake logs, setting an expiration period of less than three days.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1485.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat involves the modification of AWS S3 bucket lifecycle policies to expedite the deletion of CloudTrail logs. The technique focuses on configuring a lifecycle rule for an S3 bucket with an expiration period of fewer than three days. By shortening the retention period, attackers aim to quickly eliminate CloudTrail logs, thereby covering their tracks and impeding forensic investigations. This activity is significant because it directly targets security logging, a critical component for threat detection and incident response. This technique can be used by various threat actors seeking to evade detection within AWS environments.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account, potentially through compromised credentials or a vulnerability.
2.  The attacker identifies the S3 bucket used to store CloudTrail logs.
3.  The attacker uses AWS CLI or the AWS Management Console to execute the `PutBucketLifecycle` API call.
4.  The `PutBucketLifecycle` call modifies the lifecycle configuration of the S3 bucket.
5.  The new lifecycle rule specifies a short expiration period (less than three days) for objects in the bucket.
6.  CloudTrail logs within the S3 bucket are automatically deleted after the specified expiration period.
7.  The attacker's actions are no longer recorded in CloudTrail, hindering incident response.

## Impact

Successful execution of this attack leads to the rapid and irreversible deletion of CloudTrail logs. This can severely hamper incident response efforts, making it difficult to trace attacker actions, identify the scope of a breach, and conduct thorough forensic analysis. Organizations may be unable to meet compliance requirements related to data retention and audit logging.

## Recommendation

*   Deploy the provided Sigma rule to detect suspicious `PutBucketLifecycle` events with short expiration periods in your SIEM.
*   Investigate any detected `PutBucketLifecycle` events modifying S3 bucket lifecycle policies (logsource: `ASL AWS CloudTrail`).
*   Monitor AWS CloudTrail logs for unusual API calls related to S3 bucket lifecycle management (logsource: `ASL AWS CloudTrail`).
