---
title: AWS Network Access Control List Created with All Open Ports
slug: 2024-01-aws-open-nacls
description: An AWS Network Access Control List (NACL) configured to allow all ports and protocols, potentially exposing resources to unauthorized access.
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
  - misconfiguration
vendors:
  - AWS
products:
  - AWS Network Access Control List
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_network_access_control_list_created_with_all_open_ports.yml
rules:
  - title: AWS NACL Created with All Open Ports
    description: Detects the creation of an AWS Network ACL with ingress and egress rules allowing all traffic (0.0.0.0/0).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS NACL Modified to Allow All Open Ports
    description: Detects the modification of an AWS Network ACL to allow ingress and egress traffic from all sources (0.0.0.0/0).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert identifies a potentially misconfigured AWS Network Access Control List (NACL). NACLs act as a firewall for controlling traffic in and out of one or more subnets. When a NACL is configured to allow all ports and protocols (0.0.0.0/0 for all traffic), it effectively bypasses network-level security controls. While there may be legitimate reasons for such a configuration, it often indicates a security oversight, such as a default configuration not properly secured or an intentional circumvention of security policies. The creation of overly permissive NACLs can lead to significant risk by allowing unrestricted network access to critical resources, potentially leading to data breaches, unauthorized access, or other malicious activities. This detection focuses on the misconfiguration itself, regardless of the actor or intent behind it.

## Attack Chain

1.  An attacker identifies a target AWS environment.
2.  The attacker identifies or creates a new AWS Network ACL with ingress and egress rules allowing all traffic (0.0.0.0/0).
3.  The attacker associates this overly permissive NACL with one or more subnets within the target AWS Virtual Private Cloud (VPC).
4.  The attacker leverages the open NACL to scan for vulnerable services and systems within the associated subnets.
5.  The attacker exploits identified vulnerabilities to gain initial access to a system within the subnet.
6.  The attacker moves laterally to other systems within the open network segment.
7.  The attacker escalates privileges to gain administrative control of the environment.
8.  The attacker exfiltrates sensitive data or deploys malicious payloads such as ransomware.

## Impact

The creation of a Network Access Control List with all open ports significantly expands the attack surface of the affected AWS environment. Successful exploitation could lead to unauthorized access to sensitive data, system compromise, data breaches, and potential financial loss. The scope of impact depends on the resources exposed by the open NACL and the attacker's ability to move laterally within the environment.

## Recommendation

*   Implement the Sigma rule `AWS NACL Created with All Open Ports` to detect the creation of overly permissive NACLs and trigger investigation.
*   Regularly review and audit existing NACL configurations to identify and remediate overly permissive rules.
*   Implement the principle of least privilege when configuring NACLs, allowing only necessary traffic.
*   Enable AWS CloudTrail logging and monitor for NACL creation events to ensure proper oversight and detection.
*   Implement alerting for changes to NACL configurations in your SIEM/SOAR platform based on the `aws_network_access_control_list_created_with_all_open_ports.yml` detection logic.
