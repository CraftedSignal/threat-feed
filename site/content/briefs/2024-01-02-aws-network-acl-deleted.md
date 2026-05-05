---
title: AWS Network Access Control List Deletion Detected
slug: 2024-01-02-aws-network-acl-deleted
description: Detection of AWS Network Access Control List (ACL) deletion using AWS CloudTrail logs, which can remove critical access restrictions, potentially allowing unauthorized access to cloud instances and leading to data exfiltration or further compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - network
vendors:
  - Amazon
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Amazon Web Services
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_network_access_control_list_deleted.yml
rules:
  - title: Detect AWS Network ACL Entry Deletion via CloudTrail
    description: Detects the deletion of AWS Network ACL entries using AWS CloudTrail logs. This activity is significant as it can weaken network security controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Network ACL Activity via ASL
    description: Detects deletion of AWS Network ACL entries by looking at api operations in Amazon Security Lake.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the deletion of AWS Network Access Control Lists (ACLs) within an Amazon Web Services (AWS) environment. The activity is logged via AWS CloudTrail and analyzed using Amazon Security Lake (ASL). The deletion of network ACLs is a significant security event as it can effectively remove network segmentation and access control rules, potentially opening up cloud instances to unauthorized access. This analytic focuses on identifying successful `DeleteNetworkAclEntry` operations. Defenders should be aware of this activity, investigate any unexpected or unauthorized deletions, and validate that network security controls remain effective.

## Attack Chain

1.  An attacker gains initial access to an AWS account through compromised credentials or other means.
2.  The attacker authenticates to the AWS environment and assumes a role with sufficient permissions to modify network ACLs.
3.  The attacker uses the AWS API or CLI to identify the target network ACL.
4.  The attacker issues a `DeleteNetworkAclEntry` API call to remove one or more entries from the ACL.
5.  AWS CloudTrail logs the `DeleteNetworkAclEntry` event with a status of `Success`.
6.  The attacker repeats steps 3-5 to remove additional ACL entries as needed.
7.  The removed ACL entries create new network access paths, potentially allowing unauthorized access to resources.
8.  The attacker exploits the newly opened access to compromise cloud instances, exfiltrate data, or establish persistence.

## Impact

Successful deletion of network ACLs can significantly weaken an AWS environment's security posture. If an attacker successfully deletes critical ACL entries, they can bypass existing network security controls, leading to unauthorized access to sensitive resources. This can result in data exfiltration, system compromise, and potential disruption of services. The impact can vary depending on the scope of the deleted ACL entries and the resources they protected.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized AWS Network ACL deletions, focusing on the `DeleteNetworkAclEntry` operation.
*   Investigate any detected instances of network ACL deletion by correlating with other security events and user activity to determine legitimacy.
*   Review and validate AWS IAM policies to ensure that the principle of least privilege is enforced, minimizing the number of users and roles with permissions to modify network ACLs.
*   Enable Amazon Security Lake and configure it to collect AWS CloudTrail logs to provide comprehensive visibility into AWS API activity.
*   Monitor AWS CloudTrail logs for changes to other network security configurations, such as security groups and route tables.
