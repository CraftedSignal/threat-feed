---
title: Monitoring Unauthorized AWS Security Group Modifications
slug: 2026-08-aws-vpc-ingress-exposure
description: Adversaries modify AWS VPC security group ingress rules to permit unrestricted external access to sensitive management ports, facilitating remote access or future exploitation of cloud instances.
date: "2026-08-24T09:46:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Amazon
products:
  - EC2
  - VPC
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may add these rules to allow remote access to VPC instances from any location, increasing the attack surface.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Adversaries may add these rules to allow remote access to VPC instances from any location.
    confidence_band: high
rules:
  - title: Detect Insecure AWS EC2 Security Group Ingress Modification
    description: Detects unauthorized addition of ingress rules allowing unrestricted access (0.0.0.0/0) to remote access ports (SSH, RDP, etc.) in AWS EC2.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1133
      - T1562.007
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Cloud Security
    - Detection Engineering
  immediate_actions:
    - action: Review recent AuthorizeSecurityGroupIngress events for unauthorized cidrIp values.
      owner: SOC
      due: 24h
      evidence: General monitoring advice for cloud defense evasion.
  mitigation_plan:
    - priority: immediate
      action: Audit all security groups for public ingress on ports 22, 3389, and similar management services.
      owner: IT Operations
      addresses: T1562.007
      evidence: Best practice for hardening VPC configurations.
---

Security teams must monitor for unauthorized modifications to AWS VPC security group ingress rules that permit traffic from all IP addresses (0.0.0.0/0 or ::/0) to sensitive remote management ports. Adversaries leverage this technique to establish persistent access or provide a conduit for further exploitation of EC2 instances. By modifying cloud firewalls, attackers can bypass perimeter restrictions and expose instances to the public internet, increasing the attack surface significantly. While legitimate administrative workflows - such as automated CI/CD deployments or maintenance windows - may perform similar actions, malicious modification is often characterized by the absence of expected service account signatures (e.g., Terraform or Pulumi user agents) or unexpected geographic origins. Monitoring for these specific CloudTrail events is essential for detecting the abuse of cloud management privileges.

## Impact

Successful exploitation allows attackers to bypass network-level security controls, providing direct remote access to EC2 instances via protocols like SSH (22) or RDP (3389). This exposure can lead to unauthorized data exfiltration, lateral movement within the cloud environment, or the deployment of additional malicious payloads. Improperly configured security groups remain a leading cause of accidental and intentional cloud resource compromise.

## Recommendation

- Deploy the provided Sigma rule to identify unauthorized ingress modifications in AWS CloudTrail logs.
- Audit all existing VPC security groups to ensure they adhere to the principle of least privilege, explicitly removing rules that allow unrestricted access (0.0.0.0/0) to sensitive ports.
- Implement service-control policies (SCPs) or IAM policies that restrict the ability to modify security group ingress rules to only authorized, audited service accounts.
- Review CloudTrail logs for events matching 'AuthorizeSecurityGroupIngress' where the requestor does not match known automation tool user agents.
