---
title: AWS Network ACL Deletion Detected
slug: 2024-01-aws-acl-delete
description: Detection of AWS Network Access Control List (ACL) deletion via CloudTrail logs indicating potential unauthorized access or data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - network-acl
  - privilege-escalation
vendors:
  - Amazon
  - Splunk
products:
  - AWS CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_network_access_control_list_deleted.yml
rules:
  - title: AWS Network ACL Entry Deletion
    description: Detects the deletion of AWS Network ACL entries, which can lead to unauthorized network access.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Network ACL Deleted by User
    description: Detects a user deleting an entire AWS Network ACL, which can remove critical network access controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic identifies the deletion of AWS Network Access Control Lists (ACLs), a critical security control, using AWS CloudTrail logs. The detection focuses on `DeleteNetworkAclEntry` events, triggered when a user removes a network ACL entry. This is significant because deleting a network ACL can inadvertently or maliciously remove critical access restrictions, potentially opening cloud instances to unauthorized access. The targeted action allows attackers to bypass network security controls, potentially leading to data exfiltration or further compromise of the cloud environment. The detection leverages logs from AWS CloudTrail and requires the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later).

## Attack Chain

1. An attacker gains initial access to an AWS account, possibly through compromised credentials or exploiting a vulnerability in an application running on EC2.
2. The attacker enumerates existing Network ACLs to identify potential targets for modification or deletion.
3. The attacker identifies a Network ACL that, when removed or modified, would grant them broader access to resources within the VPC.
4. The attacker uses AWS CLI or AWS Management Console to issue a `DeleteNetworkAclEntry` command, targeting the chosen ACL.
5. AWS CloudTrail logs the `DeleteNetworkAclEntry` event, capturing details such as the user identity, timestamp, and affected ACL.
6. The targeted Network ACL entry is removed, altering the network access rules for the associated subnets.
7. The attacker leverages the new network access to connect to previously restricted resources, such as databases or internal applications.
8. The attacker exfiltrates sensitive data or performs other malicious activities, bypassing network-level security controls.

## Impact

Successful deletion of a network ACL entry can lead to unauthorized access to critical AWS resources, potentially affecting all instances within the affected subnets. The impact can range from data breaches and service disruption to full compromise of the cloud environment, and depends on the scope and importance of the now-exposed resources. This poses a significant threat to organizations utilizing AWS, potentially impacting confidentiality, integrity, and availability.

## Recommendation

*   Deploy the Sigma rule `AWS Network ACL Entry Deletion` to detect instances of ACL entry deletion based on `DeleteNetworkAclEntry` events in AWS CloudTrail.
*   Investigate any detected instances of `DeleteNetworkAclEntry` events, paying close attention to the user identity (`user`), source IP (`src`), and the specific ACL being modified.
*   Enable and review CloudTrail logs regularly to ensure proper coverage of AWS API activity, as indicated in the `data_source` section.
*   Implement multi-factor authentication (MFA) for all AWS accounts to mitigate the risk of compromised credentials leading to unauthorized ACL modifications.
*   Implement the `aws_network_access_control_list_deleted_filter` macro to reduce false positives.
