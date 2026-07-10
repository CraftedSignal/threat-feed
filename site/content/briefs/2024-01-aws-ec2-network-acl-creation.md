---
title: AWS EC2 Network Access Control List Creation
slug: 2024-01-aws-ec2-network-acl-creation
description: The rule detects the creation of an AWS EC2 network access control list (ACL) or an entry in a network ACL with a specified rule number, which adversaries may exploit to establish persistence or defense evasion by creating permissive rules.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - ec2
  - network-acl
  - persistence
  - defense-evasion
vendors:
  - AWS
products:
  - Amazon EC2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl-entry.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html
rules:
  - title: AWS EC2 Network ACL Creation
    description: Detects the creation of an AWS EC2 Network ACL.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Network ACL Entry Creation
    description: Detects the creation of an AWS EC2 Network ACL Entry.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies the creation of AWS EC2 network access control lists (ACLs) or entries within them. EC2 Network ACLs act as stateless firewalls, controlling inbound and outbound traffic at the subnet level. Attackers may create overly permissive rules in these ACLs to maintain persistence, bypass security controls, or potentially exfiltrate data. This activity is typically logged in AWS CloudTrail, providing a valuable data source for detection. The rule focuses on successful creation events of ACLs or their entries, aiming to identify unauthorized modifications indicative of persistence tactics or defense evasion. Monitoring these events helps in the early detection of malicious activities related to network access control misconfigurations.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a vulnerability in an application.
2. The attacker leverages these credentials to interact with the AWS EC2 service via the AWS CLI or API.
3. The attacker initiates the creation of a new Network ACL using the `CreateNetworkAcl` API call, or adds a new entry to an existing ACL using the `CreateNetworkAclEntry` API call.
4. The newly created ACL or entry is configured with overly permissive rules, such as allowing all inbound or outbound traffic on specific ports or from any IP address.
5. The attacker modifies the subnet association to apply the malicious Network ACL to a specific subnet, granting broad network access.
6. The permissive ACL rules enable the attacker to establish persistent access to resources within the subnet, bypass existing security controls, or facilitate data exfiltration.
7. The attacker maintains persistence by ensuring the malicious ACL remains active and associated with the target subnet, granting continued unauthorized access.

## Impact

Successful exploitation can lead to unauthorized access to resources within the AWS environment, allowing attackers to move laterally, exfiltrate sensitive data, or maintain a persistent foothold. While this rule is low severity, the impact can be significant depending on the scope and permissions granted by the new network ACL. A permissive network ACL can override security group rules, and potentially expose services to the internet.

## Recommendation

*   Deploy the Sigma rule to your SIEM and tune for your environment.
*   Review AWS CloudTrail logs for `CreateNetworkAcl` and `CreateNetworkAclEntry` events and investigate any unexpected activity from unfamiliar users.
*   Implement alerting on changes to Network ACLs to proactively identify potentially malicious activity.
*   Enforce the principle of least privilege for IAM users and roles to minimize the risk of unauthorized changes to network configurations.
*   Implement multi-factor authentication (MFA) to protect against compromised credentials.
*   Regularly audit AWS IAM policies and permissions to identify and remediate overly permissive access.
