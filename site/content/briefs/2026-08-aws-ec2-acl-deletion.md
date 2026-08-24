---
title: AWS EC2 Network ACL Deletion Defense Evasion
slug: 2026-08-aws-ec2-acl-deletion
description: Adversaries may delete AWS EC2 Network Access Control Lists (ACLs) or their ingress/egress entries to disable network-level security controls and facilitate unauthorized access or data exfiltration.
date: "2026-08-24T09:46:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - aws
vendors:
  - Amazon
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may delete these ACLs to disable security controls, facilitating unauthorized access or data exfiltration.
    confidence_band: high
rules:
  - title: Detect AWS EC2 Network ACL Deletion
    description: Detects successful deletion of an EC2 Network ACL or ACL entry, excluding activity from known infrastructure-as-code tools.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review CloudTrail for historical ACL deletions
      owner: SOC
      due: 48h
      evidence: General threat intelligence on cloud defense evasion
  hunt_leads:
    - lead: Identify accounts performing high volumes of network modifications
      technique_id: T1562.007
      data_needed:
        - CloudTrail Management Events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Analysis of cloud environment logs for unauthorized firewall changes
---

Adversaries targeting AWS environments may attempt to impair security defenses by modifying or deleting Network Access Control Lists (ACLs) within a Virtual Private Cloud (VPC). By removing these firewall layers, attackers can bypass traffic filtering, enable lateral movement, or facilitate the exfiltration of sensitive data. This activity typically manifests as API calls within AWS CloudTrail, specifically targeting the `DeleteNetworkAcl` or `DeleteNetworkAclEntry` actions. Because Network ACLs are critical for subnet security, unauthorized deletions are significant indicators of potential defense evasion. Organizations must distinguish these malicious modifications from legitimate infrastructure-as-code (IaC) updates, such as those performed by Terraform, Pulumi, or Ansible, which may legitimately manage network configurations in automated environments.

## Impact

Successful deletion of Network ACLs exposes subnets to unauthorized inbound and outbound traffic, effectively nullifying intended network security perimeters. This can result in unauthorized access to sensitive internal resources, facilitate command-and-control communication, or enable the unauthorized exfiltration of data from the affected VPC subnets.

## Recommendation

- Deploy the Sigma-compatible rule below to monitor for unauthorized Network ACL deletions in AWS CloudTrail logs.
- Establish a baseline of authorized administrative and IaC service accounts to tune out legitimate network configuration changes.
- Implement AWS CloudTrail alerts for `DeleteNetworkAcl` and `DeleteNetworkAclEntry` events, prioritizing alerts that lack association with recognized automated deployment roles.
- Review IAM policies to ensure that only essential roles possess permissions for `ec2:DeleteNetworkAcl` and `ec2:DeleteNetworkAclEntry` actions.
- Enable VPC Flow Logs to monitor traffic patterns following any detected modifications to network security configurations.
