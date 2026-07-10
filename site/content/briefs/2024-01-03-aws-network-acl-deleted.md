---
title: AWS Network Access Control List Deletion Detected
slug: 2024-01-03-aws-network-acl-deleted
description: Detection of AWS Network Access Control List (ACL) deletion events via CloudTrail logs indicates a potential attempt to weaken network security controls.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - network-acl
  - defense-evasion
vendors:
  - AWS
products:
  - AWS Network Access Control List
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_network_access_control_list_deleted.yml
rules:
  - title: Detect AWS Network ACL Entry Deletion via CloudTrail
    description: Detects the deletion of AWS Network ACL entries by monitoring AWS CloudTrail logs for the `DeleteNetworkAclEntry` event, indicating a potential attempt to weaken network security controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Network ACL Egress Rule Deletion
    description: Detects the deletion of AWS Network ACL Egress rules by monitoring AWS CloudTrail logs for the `DeleteNetworkAclEntry` event where `requestParameters.egress` is `true`.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Network ACL Entry Deletion by User Agent
    description: Detects AWS Network ACL Entry Deletion by filtering on userAgent
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

This brief focuses on the detection of AWS Network Access Control List (ACL) deletions using AWS CloudTrail logs. The deletion of a network ACL entry, specifically the `DeleteNetworkAclEntry` event, is a critical event that could indicate a malicious actor attempting to bypass existing network security controls. These ACLs are designed to restrict network access, so their removal can expose cloud instances to unauthorized access, data exfiltration, and further compromise. The source Splunk analytic leverages AWS CloudTrail data to detect instances where a user deletes a network ACL entry. Early detection of this activity is crucial for maintaining the integrity and security of AWS environments. The detection logic requires the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later).

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a vulnerability. (T1566)
2.  The attacker enumerates existing Network ACLs to identify potential targets for deletion. (T1082)
3.  The attacker executes the `DeleteNetworkAclEntry` command, removing specific rules from the targeted ACLs. (T1562.007)
4.  CloudTrail logs the `DeleteNetworkAclEntry` event, capturing details such as the user, timestamp, and affected ACL.
5.  The monitoring system detects the deletion event based on the CloudTrail logs.
6.  The deletion of the ACL entry weakens the network security posture, potentially opening unauthorized access to resources.
7.  The attacker exploits the newly opened network paths to access previously protected resources.
8.  The attacker achieves their objective, such as data exfiltration, lateral movement, or resource compromise.

## Impact

The successful deletion of network ACL entries can have severe consequences, including unauthorized access to sensitive data, compromise of critical systems, and potential data exfiltration. This can lead to financial losses, reputational damage, and regulatory penalties. If an attacker successfully removes key ACLs, they can bypass network segmentation and gain access to previously isolated environments, potentially impacting hundreds or thousands of instances, depending on the scale of the AWS deployment.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect AWS Network ACL deletions using CloudTrail logs.
*   Investigate any detected `DeleteNetworkAclEntry` events in CloudTrail to determine the legitimacy of the activity and the user involved.
*   Enable and review CloudTrail logs regularly to ensure comprehensive monitoring of AWS environment changes.
*   Enforce multi-factor authentication (MFA) for all AWS accounts to mitigate the risk of compromised credentials.
*   Implement principle of least privilege to limit the number of IAM roles that are able to modify Network ACLs.
