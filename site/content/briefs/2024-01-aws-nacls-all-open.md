---
title: AWS Network ACL Created with All Ports Open
slug: 2024-01-aws-nacls-all-open
description: The analytic detects the creation or replacement of AWS Network Access Control Lists (ACLs) with rules that allow all traffic from a specified CIDR block, potentially exposing the network to unauthorized access and increasing the risk of data breaches.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - network-acl
  - misconfiguration
  - cloud
  - security-group
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Amazon Security Lake
  - Splunk Add-on for Amazon Web Services
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_network_access_control_list_created_with_all_open_ports.yml
rules:
  - title: AWS Network ACL Created with All Ports Open
    description: Detects the creation or modification of an AWS Network ACL with rules allowing all traffic from 0.0.0.0/0.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - network_connection
      - aws
  - title: AWS NACL Modified to Allow All Traffic
    description: Detects modifications to an existing AWS NACL to allow all traffic (0.0.0.0/0).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - network_connection
      - aws
rules_count: 2
---

This detection focuses on identifying misconfigured AWS Network ACLs (NACLs) that permit unrestricted traffic. AWS NACLs act as a firewall for controlling traffic in and out of subnets within a Virtual Private Cloud (VPC). When an NACL is configured to allow all ports and protocols from any IP address (0.0.0.0/0), it effectively bypasses security controls and exposes resources to potential threats. The activity is detected by monitoring AWS CloudTrail events for `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` API calls. This configuration error can be introduced by administrators during initial setup or through misconfiguration during updates. Defenders should ensure that NACLs follow the principle of least privilege to limit the attack surface.

## Attack Chain

1.  An attacker identifies a target AWS environment.
2.  The attacker scans for publicly accessible services or resources.
3.  An administrator, either maliciously or accidentally, creates or modifies a Network ACL using the AWS Management Console, CLI, or API with overly permissive rules (allowing all traffic: `ruleAction=allow AND egress=false AND aclProtocol=-1 AND cidrBlock=0.0.0.0/0`).
4.  The misconfigured NACL is applied to one or more subnets within the VPC.
5.  The attacker exploits the open ports and protocols to gain unauthorized access.
6.  The attacker attempts to move laterally within the AWS environment.
7.  The attacker exfiltrates sensitive data or disrupts services.

## Impact

A misconfigured Network ACL that allows all traffic can have severe consequences. It can lead to unauthorized access to sensitive data, potential data breaches, service disruption, and further compromise of the AWS environment. The impact is particularly high if critical resources are located within the affected subnets. This type of misconfiguration violates security best practices and compliance requirements.

## Recommendation

*   Deploy the Sigma rule `AWS Network ACL Created with All Ports Open` to your SIEM to detect this specific misconfiguration (logsource: `ASL AWS CloudTrail`, category: `network_connection`).
*   Review existing Network ACL configurations to identify and remediate any overly permissive rules (check AWS console or use AWS CLI/API).
*   Implement automated checks to validate Network ACL configurations against security best practices.
*   Ensure that NACLs follow the principle of least privilege by only allowing necessary traffic (review NACL `ruleAction`, `egress`, `aclProtocol`, and `cidrBlock` settings in CloudTrail logs).
*   Investigate any identified instances of overly permissive NACL configurations to determine the root cause and potential impact (analyze CloudTrail logs for `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` events).
