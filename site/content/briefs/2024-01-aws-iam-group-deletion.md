---
title: Successful AWS IAM Group Deletion Detection
slug: 2024-01-aws-iam-group-deletion
description: Successful deletion of an AWS IAM group, while not inherently malicious, can indicate insider threat activity, account compromise, or attempts to remove audit trails, and should be monitored.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - cloud
  - deletion
vendors:
  - AWS
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_iam_successful_group_deletion.yml
rules:
  - title: AWS IAM Successful Group Deletion
    description: Detects successful deletion of an AWS IAM group, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Group Deletion by Unusual User Agent
    description: Detects IAM Group Deletion with unusual User Agent string
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The successful deletion of an AWS Identity and Access Management (IAM) group is an action that, while legitimate in many circumstances, can also be indicative of malicious activity. An adversary with sufficient privileges or a compromised account may delete IAM groups to remove audit trails, disrupt access controls, or facilitate lateral movement within the AWS environment. While the provided content is from a Splunk detection, focusing on identifying this specific event, defenders should correlate this event with other suspicious activities to determine the intent and scope of any potential breach. This event warrants close monitoring, especially in environments with strict access control policies. Defenders should baseline normal IAM group deletion activity to reduce false positives, as well as look for suspicious deletion patterns or deviations from established administrative practices.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account with sufficient IAM privileges, potentially through compromised credentials or exploiting a misconfigured IAM role.
2.  The attacker enumerates existing IAM groups to identify potential targets for deletion.
3.  The attacker uses the AWS CLI, SDK, or Management Console to initiate the deletion of a specific IAM group.
4.  AWS validates the request and confirms that the user or role has the required permissions to delete the group.
5.  The IAM group is successfully deleted, removing all users and policies associated with the group.
6.  The attacker may then proceed to delete associated IAM users and roles or modify other IAM configurations to further obfuscate their actions or maintain persistence.
7.  The attacker covers their tracks by deleting CloudTrail logs, disabling monitoring, or creating new IAM users/roles for persistent access.

## Impact

Successful deletion of an AWS IAM group can lead to disruption of services, unauthorized access, and data breaches. If critical roles or users are associated with the deleted group, legitimate users may lose access to essential resources. This can halt business operations, damage reputation, and potentially lead to financial losses due to downtime and recovery efforts. A successful attack can also impair incident response by removing audit trails.

## Recommendation

*   Deploy the `AWS IAM Group Deletion Detection` Sigma rule to your SIEM and tune for your environment to detect potential malicious activity.
*   Enable AWS CloudTrail logging in all regions and monitor the `eventName: DeleteGroup` to capture IAM group deletion events.
*   Review IAM policies to ensure the principle of least privilege and restrict IAM group deletion permissions to only authorized personnel.
*   Implement multi-factor authentication (MFA) for all IAM users and enforce strong password policies to prevent account compromise.
