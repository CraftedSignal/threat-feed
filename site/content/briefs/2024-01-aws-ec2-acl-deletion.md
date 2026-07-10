---
title: AWS EC2 Network Access Control List Deletion
slug: 2024-01-aws-ec2-acl-deletion
description: The deletion of an Amazon EC2 network access control list (ACL) or its entries can indicate an attacker attempting to disable security controls for unauthorized access or data exfiltration.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ec2
  - network-security
  - defense-evasion
vendors:
  - AWS
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAcl.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl-entry.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAclEntry.html
rules:
  - title: AWS EC2 Network ACL Deletion Detected
    description: Detects the deletion of an AWS EC2 Network ACL or entry via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Network ACL Deletion by Unauthorized User
    description: Detects the deletion of an AWS EC2 Network ACL or entry by a user not in the allowed list.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection brief focuses on identifying the deletion of Amazon Elastic Compute Cloud (EC2) Network Access Control Lists (ACLs) or their ingress/egress entries. EC2 Network ACLs act as a firewall for controlling traffic to subnets. An attacker may delete these ACLs to evade defenses, enabling unauthorized access or data exfiltration. This activity is logged in AWS CloudTrail, providing an opportunity for detection. This rule specifically looks for `DeleteNetworkAcl` or `DeleteNetworkAclEntry` events with a successful outcome in CloudTrail logs. The scope of targeting is AWS environments utilizing EC2 and Network ACLs.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or an exploited IAM role.
2. The attacker enumerates existing EC2 Network ACLs using AWS CLI or API calls to identify potential targets for disabling.
3. The attacker identifies the target Network ACLs that control access to valuable resources or subnets.
4. The attacker uses the `DeleteNetworkAcl` or `DeleteNetworkAclEntry` API calls via the AWS CLI, SDK, or Management Console to remove the identified ACLs or their specific rules.
5. AWS CloudTrail logs record the successful deletion of the Network ACL or ACL entry, including the user identity and source IP address.
6. With the Network ACL removed, the targeted subnets are now exposed to broader network traffic, bypassing the intended security controls.
7. The attacker exploits the now-unprotected subnet to gain unauthorized access to resources, systems, or data within the subnet.
8. The attacker may then proceed with data exfiltration, lateral movement, or other malicious activities, leveraging the lack of network access controls.

## Impact

Successful deletion of Network ACLs can lead to significant security breaches. Without ACLs, subnets are exposed to potentially malicious traffic, which could lead to unauthorized access, data breaches, or the deployment of malicious software. The number of affected subnets depends on the scope of the deleted ACLs. The impact could range from a single compromised application to a widespread network compromise.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `DeleteNetworkAcl` or `DeleteNetworkAclEntry` events in AWS CloudTrail logs.
*   Review AWS CloudTrail logs for suspicious activity around the time of detected ACL deletions, focusing on the user identity and source IP address (see the rule's investigation fields).
*   Implement strict IAM policies following the principle of least privilege to restrict the ability to delete Network ACLs to authorized personnel only.
*   Monitor AWS accounts for unusual activity, like creation of new IAM policies or roles that could grant excessive permissions.
*   Enforce multi-factor authentication (MFA) for all AWS accounts, especially those with permissions to modify network configurations.
