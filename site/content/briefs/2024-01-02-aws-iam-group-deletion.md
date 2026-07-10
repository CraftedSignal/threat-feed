---
title: AWS IAM Group Deletion Detected
slug: 2024-01-02-aws-iam-group-deletion
description: Detection of AWS IAM group deletion via the DeleteGroup API call, which may indicate an attacker removing audit trails, disrupting operations, or concealing privileged access activity.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - iam
  - cloudtrail
  - impact
  - account-access-removal
vendors:
  - Amazon Web Services
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html
  - https://attack.mitre.org/techniques/T1531/
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS IAM Group Deletion Detected
    description: Detects when an IAM group is deleted using the DeleteGroup API call in AWS CloudTrail logs, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS IAM Related Actions Before Group Deletion
    description: Detects IAM actions commonly performed before deleting a group, such as detaching policies or removing users.
    platform: sigma
    severity: informational
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

This alert focuses on the detection of IAM group deletions within Amazon Web Services (AWS) environments. The rule triggers when the `DeleteGroup` API call is observed in AWS CloudTrail logs, indicating that an IAM group has been removed. While legitimate IAM group deletions occur, this action can also be indicative of malicious activity. Adversaries may delete IAM groups to erase evidence of their presence, disrupt operations by removing necessary permissions for users or services, or hide their actions after using the group to gain privileged access. This activity often follows the successful exploitation of a vulnerability or the compromise of an account. Detecting this activity provides security teams with a chance to investigate potential unauthorized access, policy changes, or other malicious actions performed using the deleted group's privileges. It is important to correlate this activity with other events in the environment to determine if it is part of a broader attack campaign.

## Attack Chain

1. **Initial Access:** An attacker gains initial access to the AWS environment through compromised credentials or by exploiting a vulnerability in a service.
2. **Privilege Escalation:** The attacker attempts to elevate their privileges to gain more control over the AWS environment, potentially by attaching policies to themselves or assuming roles.
3. **Lateral Movement:** The attacker moves laterally within the AWS environment, accessing different resources and services using their elevated privileges.
4. **Resource Access:** The attacker accesses sensitive resources, such as data stores, applications, or infrastructure components, to gather information or achieve their objectives.
5. **Credential Access:** The attacker attempts to steal additional credentials, such as IAM user credentials or EC2 instance profiles, to further expand their access and maintain persistence.
6. **Policy Modification/Attachment:** The attacker may modify IAM policies or attach policies to IAM groups to grant themselves additional permissions or control over resources.
7. **IAM Group Deletion:** The attacker deletes an IAM group using the `DeleteGroup` API call in an attempt to remove audit trails, disrupt operations, or hide their activity after using the group for privileged access.
8. **Impact:** The attacker achieves their final objective, such as data exfiltration, system disruption, or financial gain, potentially leaving the environment in a compromised state.

## Impact

The deletion of an IAM group can lead to several negative impacts. Firstly, it can disrupt operations by removing necessary permissions for users or services that were members of the group. Secondly, it can erase audit trails by removing a key piece of evidence that could be used to track an attacker's actions. Finally, it can hide an attacker's activity after they have used the group to gain privileged access. The scope of the impact depends on the group's permissions and the resources it had access to, as well as whether or not other groups or roles can take over its functionality.

## Recommendation

*   Deploy the Sigma rule `AWS IAM Group Deletion Detected` to your SIEM and tune for your environment to detect unauthorized IAM group deletions.
*   Investigate any detected IAM group deletions to determine if they are legitimate or indicative of malicious activity, referencing the investigation steps in the rule's `note` section.
*   Monitor for related activity, such as `DetachGroupPolicy`, `RemoveUserFromGroup`, `DeleteGroupPolicy`, which often precede deletion.
*   Enforce change-control for group deletions and restrict `iam:DeleteGroup` privileges, as suggested in the rule's `note` section.
