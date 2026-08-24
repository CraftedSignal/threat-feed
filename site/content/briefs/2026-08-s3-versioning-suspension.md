---
title: Suspension of Amazon S3 Object Versioning
slug: 2026-08-s3-versioning-suspension
description: Adversaries may suspend Amazon S3 object versioning to inhibit system recovery, facilitate unauthorized data destruction, or prepare for ransomware deployment.
date: "2026-08-24T09:50:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Amazon
products:
  - S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: When object versioning is suspended for a bucket, it could indicate an adversary's attempt to inhibit system recovery following malicious activity.
    confidence_band: high
rules:
  - title: Detect S3 Object Versioning Suspension
    description: Detects when the PutBucketVersioning API is called with status set to Suspended, excluding common infrastructure-as-code tooling.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
---

Suspending S3 object versioning is a technique used by adversaries to weaken data protection mechanisms within AWS environments. By transitioning a bucket from an 'Enabled' to a 'Suspended' state via the `PutBucketVersioning` API, an attacker prevents the storage of previous object versions. This action makes it significantly easier for an actor to permanently delete or overwrite sensitive data, such as backups, logs, or audit evidence, without the possibility of recovery. While administrators may perform this action during infrastructure maintenance or cost optimization, unexpected suspension events - particularly when associated with non-automated user agents - should be treated as a potential indicator of defense evasion or pre-ransomware activity. Security teams must monitor CloudTrail for these configuration changes to ensure the integrity of critical data stores.

## Attack Chain

1. Attacker gains unauthorized access to an AWS environment via compromised IAM credentials or over-privileged roles.
2. Attacker performs reconnaissance to identify S3 buckets containing sensitive data or backups.
3. Attacker evaluates existing bucket policies and protection settings, such as versioning status.
4. Attacker invokes the `PutBucketVersioning` API operation with the `Status=Suspended` parameter to disable versioning.
5. Attacker proceeds to delete or overwrite critical objects, knowing that previous versions will not be retained for recovery.
6. Attacker may further attempt to clear CloudTrail logs or modify IAM policies to hide the activity and maintain persistence.
7. Final objective is achieved, such as data exfiltration followed by destructive ransomware deployment.

## Impact

The suspension of object versioning significantly degrades the ability of an organization to recover data following a security incident. If an attacker succeeds in disabling this feature, they can permanently destroy data, rendering cross-region replication or standard lifecycle policies ineffective for recovery. This technique is often observed in the context of cloud-based ransomware and data destruction campaigns, where the inability to recover backups increases the leverage the attacker has over the victim.

## Recommendation

- Deploy the provided Sigma rule to detect `PutBucketVersioning` events with a 'Suspended' status in AWS CloudTrail logs.
- Implement AWS Config rule `s3-bucket-versioning-enabled` to continuously monitor and alert on versioning state changes across all S3 buckets.
- Apply the principle of least privilege to IAM roles; restrict `s3:PutBucketVersioning` permissions exclusively to trusted administrative identities.
- Enable S3 Object Lock and MFA Delete for high-value buckets to provide a tamper-proof barrier against destructive actions.
- Integrate CloudTrail event analysis into SIEM workflows to correlate versioning changes with subsequent `DeleteObject` or `PutBucketPolicy` events.
