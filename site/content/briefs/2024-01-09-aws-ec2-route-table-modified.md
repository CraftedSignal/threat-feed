---
title: AWS EC2 Route Table Modification or Deletion
slug: 2024-01-09-aws-ec2-route-table-modified
description: An attacker modifies or deletes AWS EC2 route tables to disrupt network traffic, reroute communications, or maintain persistence in a compromised environment.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - cloudtrail
  - ec2
  - route-table
  - persistence
  - defense-evasion
vendors:
  - Amazon Web Services
products:
  - EC2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://github.com/easttimor/aws-incident-response#network-routing
  - https://docs.datadoghq.com/security_platform/default_rules/aws-ec2-route-table-modified/
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRoute.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRouteTableAssociation
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRouteTable.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRoute.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisassociateRouteTable.html
rules:
  - title: AWS EC2 Route Table Modified or Deleted
    description: Detects AWS CloudTrail events where an EC2 route table or association has been modified or deleted.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Route Table Modification by Unusual User Agent
    description: Detects AWS CloudTrail events where an EC2 route table is modified by an unusual user agent, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Attackers can manipulate AWS EC2 route tables to achieve various malicious objectives. Modifications or deletions of route tables and their associations, using actions like `ReplaceRoute`, `ReplaceRouteTableAssociation`, `DeleteRouteTable`, `DeleteRoute`, and `DisassociateRouteTable`, may indicate attempts to disrupt network traffic, reroute communications to attacker-controlled infrastructure, or establish persistence within the compromised AWS environment. This activity is often performed after initial access is gained through other means. Defenders should monitor these events closely for unexpected changes, particularly those originating from unfamiliar users or locations. While routine administration can trigger similar events, understanding the context and intent behind these actions is crucial to differentiating legitimate activity from malicious behavior.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or by exploiting a vulnerability in an application running within the environment.
2. The attacker enumerates existing EC2 route tables to identify potential targets for manipulation using `ec2:DescribeRouteTables`.
3. The attacker uses `ec2:ReplaceRoute` to modify a route within a route table, redirecting traffic destined for a specific CIDR block to an attacker-controlled instance.
4. Alternatively, the attacker uses `ec2:ReplaceRouteTableAssociation` to associate a subnet with a malicious route table they control, effectively hijacking traffic from that subnet.
5. To remove evidence or prevent legitimate access, the attacker might use `ec2:DeleteRouteTable` to delete a critical route table.
6. The attacker can also use `ec2:DeleteRoute` to remove specific routes which may impede their lateral movement or persistence.
7. The attacker uses `ec2:DisassociateRouteTable` to break existing subnet associations, disrupting network connectivity.
8. The final objective could be data exfiltration, denial of service, or maintaining long-term access to the compromised environment.

## Impact

Successful modification or deletion of EC2 route tables can lead to significant disruptions in network traffic, potentially causing downtime for critical applications and services. Attackers can reroute sensitive data through their own infrastructure, enabling data theft or manipulation. This activity impacts cloud infrastructure and can lead to a loss of confidentiality, integrity, and availability. The risk is elevated if critical infrastructure components are affected, requiring immediate incident response to mitigate the damage and restore normal operations.

## Recommendation

*   Enable AWS CloudTrail and monitor `ReplaceRoute`, `ReplaceRouteTableAssociation`, `DeleteRouteTable`, `DeleteRoute`, and `DisassociateRouteTable` events to detect suspicious route table modifications or deletions as described in the overview.
*   Deploy the Sigma rule "AWS EC2 Route Table Modified or Deleted" to your SIEM to detect unauthorized changes to route tables, ensuring to tune it for your specific environment.
*   Investigate the `aws.cloudtrail.user_identity.arn` field to determine the user or role initiating the action and validate their authorization to perform these operations, as described in the rule documentation.
*   Monitor the `source.ip` and `user_agent.original` fields in CloudTrail logs to identify unusual or suspicious sources of route table modifications as described in the investigation steps.
*   Implement the principle of least privilege by limiting route table modification permissions to specific trusted users, roles, or automation accounts and using IAM conditions, referencing the remediation steps from the provided documentation.
