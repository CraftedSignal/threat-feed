---
title: New AWS Network ACL Entry Creation Detected
slug: 2024-10-aws-network-acl-created
description: Detection of new Network ACL entries in AWS CloudTrail logs can indicate potential defense impairment or the opening of new attack vectors within an AWS account by an adversary.
date: "2024-10-26T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - attack.defense-impairment
  - attack.t1686.001
  - cloud
vendors:
  - Amazon
products:
  - AWS CloudTrail
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_acl_entries.yml
rules:
  - title: New Network ACL Entry Added
    description: Detects that network ACL entries have been added to a route table which could indicate that new attack vectors have been opened up in the AWS account.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
  - title: Suspicious Network ACL Creation Source IP
    description: Detects Network ACL entries creation from uncommon source IP addresses, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The creation of new Network Access Control List (ACL) entries in Amazon Web Services (AWS) environments can be a sign of malicious activity. While legitimate use cases exist, adversaries can leverage these ACL changes to impair existing defenses, create new pathways for lateral movement, or establish persistence mechanisms. This activity is logged by CloudTrail and can be monitored to identify unauthorized or suspicious modifications to network security configurations. Attackers could create overly permissive rules that allow unauthorized access to critical resources or restrictive rules that disrupt legitimate traffic. Monitoring the creation of Network ACL entries is important for maintaining the integrity and security of AWS environments.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or an exploited vulnerability.
2.  The attacker identifies the existing Network ACLs within the target Virtual Private Cloud (VPC).
3.  The attacker uses the AWS Management Console, CLI, or API to create a new Network ACL entry. The `CreateNetworkAclEntry` event is logged in CloudTrail.
4.  The new ACL entry may be configured to allow specific inbound or outbound traffic that was previously blocked, effectively opening a new attack vector.
5.  Alternatively, the new ACL entry may be configured to deny legitimate traffic, causing a denial-of-service condition for specific services or resources.
6.  The attacker leverages the newly created ACL entry to move laterally within the AWS environment, accessing previously inaccessible resources.
7.  The attacker performs malicious actions, such as data exfiltration or resource compromise, using the newly opened network pathways.

## Impact

The creation of unauthorized Network ACL entries can have significant consequences. It can lead to the opening of new attack vectors, allowing unauthorized access to sensitive data and critical resources. In some scenarios, it can result in a denial-of-service condition, disrupting legitimate business operations. Depending on the scope of the compromised resources and data, the impact can range from minor inconvenience to significant financial loss and reputational damage. Early detection of this activity is crucial to mitigating potential risks.

## Recommendation

*   Deploy the Sigma rule "New Network ACL Entry Added" to your SIEM to detect suspicious ACL modifications (logsource: aws, service: cloudtrail).
*   Investigate any `CreateNetworkAclEntry` events that deviate from established baseline configurations or involve unexpected source/destination IP ranges.
*   Review and audit existing Network ACL configurations regularly to identify and remediate any overly permissive or restrictive rules.
*   Implement multi-factor authentication (MFA) for all AWS accounts to reduce the risk of credential compromise and unauthorized access.
*   Monitor CloudTrail logs for other related events, such as `DeleteNetworkAclEntry` or `ReplaceNetworkAclEntry`, which may indicate further tampering with network security configurations.
