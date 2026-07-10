---
title: AWS Network ACL Created with All Ports Open
slug: 2024-01-03-aws-acl-open-ports
description: An AWS Network Access Control List (ACL) is created with all ports open, potentially exposing resources to unrestricted network access.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - network acl
vendors:
  - AWS
products:
  - Network ACL
  - Virtual Private Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_network_access_control_list_created_with_all_open_ports.yml
rules:
  - title: Detect AWS Network ACL Creation with All Ports Open
    description: Detects the creation of an AWS Network ACL configured to allow all ports, which can indicate a security misconfiguration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Network ACL Entry Creation with All Ports Open
    description: Detects the creation of an AWS Network ACL entry configured to allow all ports, which can indicate a security misconfiguration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert detects the creation of an AWS Network Access Control List (ACL) that allows traffic on all ports. While not directly indicative of malicious activity, such a configuration significantly broadens the attack surface. An overly permissive ACL makes it easier for attackers to establish unauthorized connections to resources within the VPC and potentially move laterally within the network. It is a common misconfiguration that can lead to data breaches and other security incidents. Defenders should investigate such events to confirm the business justification and ensure appropriate compensating controls are in place.

## Attack Chain

1. An attacker gains initial access to an AWS account, possibly through compromised credentials or by exploiting a misconfigured IAM role.
2. The attacker leverages the AWS CLI or Management Console to create a new Network ACL.
3. The attacker configures the Network ACL to allow inbound and outbound traffic on all ports (0-65535), effectively bypassing network segmentation controls.
4. The attacker associates the newly created, overly permissive Network ACL with one or more subnets within a Virtual Private Cloud (VPC).
5. The attacker probes the exposed resources within the subnet to identify potential targets.
6. The attacker exploits vulnerabilities in exposed services, such as databases or web applications, due to the lack of network filtering.
7. The attacker gains unauthorized access to sensitive data or systems within the VPC.

## Impact

Creating an AWS Network ACL with all ports open significantly increases the risk of unauthorized access to resources within a VPC. This misconfiguration can lead to data breaches, service disruptions, and other security incidents. The impact depends on the sensitivity of the data and systems exposed, but could potentially affect thousands of customers if it involves a multi-tenant environment. It is critical to monitor for and remediate overly permissive Network ACLs to maintain a strong security posture.
