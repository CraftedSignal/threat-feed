---
title: Insecure AWS EC2 VPC Security Group Ingress Rule Added
slug: 2024-05-aws-security-group-ingress
description: An AWS EC2 VPC security group ingress rule was added to allow traffic from any IP address (0.0.0.0/0 or ::/0) to common remote access ports, potentially exposing instances to unauthorized access and defense evasion.
date: "2024-05-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ec2
  - security-group
  - defense-evasion
vendors:
  - Amazon Web Services
products:
  - EC2
  - VPC
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupEgress.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
  - https://www.linkedin.com/pulse/my-backdoors-your-aws-infrastructure-part-3-network-micha%C5%82-brygidyn/
rules:
  - title: AWS EC2 Security Group Ingress Rule Added for Remote Access
    description: Detects when an EC2 security group ingress rule is added that allows traffic from any IP address (0.0.0.0/0 or ::/0) to common remote access ports.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1133
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Security Group Ingress Rule Added - Specific Ports
    description: Detects when an EC2 security group ingress rule is added that allows traffic to specific remote access ports (21,22,23,445,3389,5985,5986).
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1133
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the risk associated with overly permissive ingress rules in AWS EC2 VPC security groups. Specifically, it focuses on the addition of rules that allow traffic from any IP address (`0.0.0.0/0` or `::/0`) to common remote access ports such as 21 (FTP), 22 (SSH), 23 (Telnet), 445 (SMB), 3389 (RDP), 5985 (WinRM HTTP), and 5986 (WinRM HTTPS). This configuration significantly increases the attack surface of the targeted EC2 instances, making them vulnerable to brute-force attacks, credential stuffing, and other forms of unauthorized access. Elastic has identified this behavior in their detection rules as of April 2024. The targeted systems are AWS EC2 instances within a VPC.

## Attack Chain

1.  An attacker gains initial access, potentially through compromised AWS credentials or by exploiting a vulnerability in an application running on an EC2 instance.
2.  The attacker leverages the compromised credentials or instance access to interact with the AWS EC2 API.
3.  The attacker calls the `AuthorizeSecurityGroupIngress` API to modify the security group associated with the target EC2 instance.
4.  The attacker adds an ingress rule allowing traffic from any IP address (`0.0.0.0/0` or `::/0`) to a sensitive port (21, 22, 23, 445, 3389, 5985, or 5986). The specific parameters of the request are logged in CloudTrail.
5.  The security group is updated, allowing inbound connections to the target instance from any source IP.
6.  The attacker attempts to connect to the exposed port on the EC2 instance, potentially using brute-force attacks or known exploits for the service running on that port.
7.  If successful, the attacker gains unauthorized access to the EC2 instance and can perform malicious activities such as data exfiltration, lateral movement, or deploying malware.

## Impact

The successful exploitation of this misconfiguration can lead to unauthorized access to sensitive data, compromise of critical systems, and potential disruption of business operations. The number of affected instances depends on the scope of the overly permissive security group. Sectors heavily reliant on cloud infrastructure, such as finance, healthcare, and e-commerce, are particularly at risk. If successful, attackers can achieve complete control over EC2 instances and the data they contain.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect insecure security group modifications logged by CloudTrail (`event.action: AuthorizeSecurityGroupIngress`).
*   Audit existing security groups to identify and remediate overly permissive ingress rules that allow traffic from `0.0.0.0/0` or `::/0` to sensitive ports, referencing the insecure CIDRs in the IOC list.
*   Implement and enforce the principle of least privilege for security group rules, restricting access to specific IP addresses or CIDR blocks that require it.
*   Monitor AWS CloudTrail logs for suspicious activity related to security group modifications, focusing on changes made outside of normal business hours or by unauthorized users (reference log source: `aws.cloudtrail`).
