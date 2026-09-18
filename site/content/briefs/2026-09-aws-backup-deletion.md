---
title: Detection of Unauthorized AWS Backup Recovery Point Deletion
slug: 2026-09-aws-backup-deletion
description: Unauthorized deletion of AWS Backup recovery points via the DeleteRecoveryPoint API is an anti-recovery technique used by adversaries to prevent data restoration following destructive or ransomware attacks.
date: "2026-09-18T19:33:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - impact
  - cloud-security
  - aws
  - ransomware
vendors:
  - Amazon
products:
  - AWS Backup
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Deleting recovery points removes the ability to restore the associated data and is a core anti-recovery technique used in ransomware and data-destruction attacks.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_DeleteRecoveryPoint.html
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html
rules:
  - title: Detect Unauthorized AWS Backup Recovery Point Deletion
    description: Detects successful deletion of AWS Backup recovery points by a principal that is not an AWS Service, indicating potential anti-recovery activity.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for DeleteRecoveryPoint.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for AWS CloudTrail.
  hunt_leads:
    - lead: Search for mass deletion events of recovery points in CloudTrail.
      technique_id: T1490
      data_needed:
        - AWS CloudTrail management logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies mass deletion as a high-signal indicator of broader anti-recovery effort.
  mitigation_plan:
    - priority: immediate
      action: Enable AWS Backup Vault Lock in compliance mode.
      owner: IT Operations
      addresses: T1490
      evidence: Source identifies Vault Lock as a primary mitigation against recovery point deletion.
---

Adversaries targeting cloud environments often seek to inhibit system recovery to maximize the impact of data destruction or ransomware campaigns. One primary method within the AWS ecosystem is the unauthorized deletion of recovery points using the 'DeleteRecoveryPoint' API. Recovery points represent restorable backups for protected resources, including EBS volumes, RDS databases, DynamoDB tables, EFS file systems, and S3 buckets.

While the AWS Backup service performs routine lifecycle expirations for backups, deletion by a user or role principal is rare and highly suspicious. Defenders should monitor CloudTrail management events for successful 'DeleteRecoveryPoint' calls where the actor is not the 'AWSService' principal. Such activity serves as a critical indicator of potential sabotage, aiming to eliminate the victim's ability to restore operations without payment or complete manual rebuilding. This behavior often correlates with other destructive actions, such as removing Vault Locks or deleting KMS keys.

## Impact

Successful deletion of recovery points prevents the restoration of critical data, which can lead to permanent data loss for an organization. This impact is particularly severe in scenarios involving ransomware or malicious sabotage, where the inability to restore from backups forces organizations to face prolonged downtime or total data destruction. The threat targets any sector utilizing AWS Backup for data resilience, with the severity proportional to the criticality of the data hosted within the AWS environment.

## Recommendation

Prioritize the identification of unauthorized backup deletion by monitoring CloudTrail logs for 'DeleteRecoveryPoint' events.

* Deploy the provided detection logic to monitor for non-service principal calls to 'DeleteRecoveryPoint'.
* Restrict the 'backup:DeleteRecoveryPoint' IAM permission to a strictly limited set of highly trusted administrative roles.
* Implement AWS Backup Vault Lock in compliance mode to prevent the deletion of recovery points by any user, including root administrators, for a defined retention period.
* Enable and audit CloudTrail management events specifically for the 'backup.amazonaws.com' provider.
* During investigation, inspect the 'aws.cloudtrail.user_identity.arn' and 'source.ip' to determine if the deletion originates from an unauthorized entity or a compromised credential.
