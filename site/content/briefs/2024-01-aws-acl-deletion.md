---
title: AWS Network ACL Deletion Detection
slug: 2024-01-aws-acl-deletion
description: Detection of AWS Network Access Control List (ACL) deletion via CloudTrail logs, potentially indicating malicious attempts to bypass network security controls and gain unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - network acl
  - defense-evasion
vendors:
  - AWS
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_network_access_control_list_deleted.yml
rules:
  - title: AWS Network ACL Entry Deletion
    description: Detects the deletion of Network ACL entries in AWS via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Network ACL Deletion by Unusual User Agent
    description: Detects the deletion of Network ACL entries in AWS via CloudTrail logs with unusual User Agent.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the deletion of AWS Network Access Control Lists (ACLs) by monitoring AWS CloudTrail logs. It is crucial for defenders because deleting network ACLs can remove critical access restrictions, potentially allowing unauthorized access to cloud instances. The detection leverages `DeleteNetworkAclEntry` events in CloudTrail, providing visibility into administrative actions affecting network security. This is particularly relevant in environments where strict network segmentation and access controls are enforced. The deletion of an ACL entry, if malicious, could signify an attacker attempting to weaken the security posture of the cloud environment to facilitate lateral movement, data exfiltration, or other malicious activities.

## Attack Chain

1.  An attacker gains initial access to an AWS account, possibly through compromised credentials or a misconfigured IAM role (T1078).
2.  The attacker enumerates existing Network ACLs within the AWS environment to identify potential targets for modification (T1068).
3.  The attacker identifies a specific Network ACL that, when deleted, would grant broader network access (T1562.007).
4.  The attacker executes the `DeleteNetworkAclEntry` API call, removing the targeted ACL entry (T1562.007).
5.  CloudTrail logs the `DeleteNetworkAclEntry` event, including details about the actor, affected resource, and request parameters.
6.  The deletion of the ACL entry allows unauthorized network traffic to flow, potentially enabling lateral movement within the AWS environment (T1021).
7.  The attacker exploits the newly opened network access to access sensitive data or systems (T1003, T1071).
8.  The attacker exfiltrates data or deploys malicious software, leveraging the compromised network configuration (TA0010, TA0011).

## Impact

The deletion of AWS Network ACLs can lead to significant security breaches. If successful, an attacker can bypass network security controls, gain unauthorized access to sensitive resources, and potentially exfiltrate data or deploy malware. The scope of impact depends on the role of the deleted ACL, but could affect entire subnets or VPCs. This can lead to data breaches, service disruption, and reputational damage. The described scenario could affect organizations of any size utilizing AWS infrastructure, especially those in regulated industries with strict compliance requirements.

## Recommendation

*   Deploy the Sigma rule `AWS Network ACL Entry Deletion` to your SIEM and tune for your environment to detect potentially malicious ACL deletions based on CloudTrail logs.
*   Investigate any identified `DeleteNetworkAclEntry` events to determine the legitimacy of the action and the user involved.
*   Implement multi-factor authentication (MFA) for all AWS accounts, particularly those with administrative privileges, to reduce the risk of credential compromise (T1110).
*   Regularly review IAM roles and permissions to ensure least privilege access, minimizing the potential impact of compromised credentials (T1078).
*   Monitor CloudTrail logs for other suspicious API calls or activities that may indicate broader compromise (log source: ASL AWS CloudTrail).
