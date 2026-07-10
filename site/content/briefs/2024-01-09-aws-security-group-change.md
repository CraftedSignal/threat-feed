---
title: AWS EC2 Security Group Configuration Change Detection
slug: 2024-01-09-aws-security-group-change
description: Detection of unauthorized changes to AWS EC2 Security Group configurations, potentially leading to persistence, data exfiltration, or lateral movement within the AWS environment.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - security-group
  - persistence
vendors:
  - Amazon
products:
  - Elastic Compute Cloud (EC2)
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.html
  - https://attack.mitre.org/techniques/T1133/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/007/
  - https://attack.mitre.org/techniques/T1578/
  - https://attack.mitre.org/techniques/T1578/005/
rules:
  - title: AWS EC2 Security Group Creation
    description: Detects the creation of new AWS EC2 Security Groups, which could be an attempt to bypass existing network controls.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Security Group Modification - Ingress/Egress Rule Changes
    description: Detects modifications to ingress or egress rules of AWS EC2 Security Groups, potentially indicating unauthorized network access.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Security Group Modification - Instance Attribute
    description: Detects modifications to instance attributes related to Security Groups, possibly revealing attempts to reconfigure network settings.
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
rules_count: 3
---

This threat brief focuses on the detection of changes to Amazon Web Services (AWS) Elastic Compute Cloud (EC2) Security Group configurations. Security Groups act as virtual firewalls controlling inbound and outbound traffic for EC2 instances. Attackers may modify these configurations to create backdoors, exfiltrate sensitive data, or pivot to other resources within the AWS environment. This activity is often observed after initial compromise, and can be used to maintain persistence. This brief is applicable to organizations utilizing AWS EC2 services, especially those with stringent security and compliance requirements. The detection strategy focuses on monitoring AWS CloudTrail logs for specific EC2 API calls related to security group modifications.

## Attack Chain

1.  Initial Access: An attacker gains initial access to the AWS environment through compromised credentials or an exploited vulnerability (e.g., in a web application running on EC2).
2.  Privilege Escalation: The attacker escalates privileges to an IAM role or user with sufficient permissions to modify security group configurations.
3.  Discovery: The attacker enumerates existing security groups to identify targets for modification using AWS CLI or API calls.
4.  Security Group Modification: The attacker modifies the security group configurations using actions like `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, or `ModifySecurityGroupRules` to open up ports or allow traffic from malicious IP ranges (0.0.0.0/0).
5.  Persistence: The attacker establishes persistence by allowing external access to instances via SSH (port 22) or RDP (port 3389) or other services.
6.  Lateral Movement: The attacker uses the newly opened security group rules to move laterally to other instances within the VPC, accessing sensitive data or deploying malware.
7.  Data Exfiltration: The attacker modifies egress rules to allow outbound traffic to attacker-controlled servers, enabling exfiltration of data.

## Impact

Successful exploitation of this threat can lead to unauthorized access to sensitive data, compromise of EC2 instances, and potential data breaches. Attackers can use modified security groups to establish persistent access to the AWS environment, bypass existing security controls, and move laterally to other resources. The impact can range from data theft and service disruption to complete infrastructure compromise, depending on the permissions granted to the compromised IAM role and the value of the resources protected by the security groups. Organizations in regulated industries may face compliance violations and financial penalties as a result of such breaches.

## Recommendation

*   Deploy the provided Sigma rule to detect unauthorized modifications to AWS EC2 Security Groups based on CloudTrail logs (event.action and event.provider filters).
*   Enable AWS CloudTrail logging to ensure all API calls related to EC2 security group modifications are captured (index: "logs-aws.cloudtrail-*").
*   Review and restrict IAM permissions to limit which users and roles can modify security group configurations.
*   Monitor for modifications to security group rules that allow traffic from or to unexpected IP ranges (aws.cloudtrail.request_parameters).
*   Investigate any detected changes to security groups made by unfamiliar users or from unusual source IPs (aws.cloudtrail.user_identity.arn and source.ip).
