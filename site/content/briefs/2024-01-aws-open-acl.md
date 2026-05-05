---
title: AWS Network Access Control List Created with All Open Ports
slug: 2024-01-aws-open-acl
description: The analytic detects the creation of AWS Network Access Control Lists (ACLs) with all ports open to a specified CIDR by monitoring `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` actions with rules allowing all traffic, potentially leading to unauthorized network access.
date: "2024-01-02T12:00:00Z"
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
  - Splunk
  - AWS
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - AWS CloudTrail
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_network_access_control_list_created_with_all_open_ports.yml
rules:
  - title: AWS Network ACL Created with All Open Ports
    description: Detects the creation or replacement of AWS Network ACL entries that allow all ports.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Network ACL Created with Wide Port Range
    description: Detects the creation or replacement of AWS Network ACL entries with a wide port range (greater than 1024).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the creation of overly permissive Network Access Control Lists (ACLs) within Amazon Web Services (AWS). Specifically, it focuses on `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` CloudTrail events where rules are configured to allow all traffic (all ports open) to a defined CIDR block. Such configurations drastically reduce network security posture by potentially exposing critical services and data to unauthorized access. The timeframe of concern is ongoing as long as such misconfigurations exist. This matters to defenders because an attacker could leverage such an opening to pivot deeper into the AWS environment, leading to data exfiltration or service disruption.

## Attack Chain

1. An attacker gains initial access to an AWS account through compromised credentials or other means (e.g., exposed API keys).
2. The attacker uses the AWS CLI or Management Console to create a new Network ACL or modify an existing one.
3. The attacker configures the ACL rule to allow all inbound traffic (0.0.0.0/0 for all IPv4 addresses) on all ports by setting `requestParameters.ruleAction` to "allow" and `requestParameters.aclProtocol` to "-1".
4. If not opening all ports the attacker creates ACL rule to allow all inbound traffic on ports with range larger than 1024 setting the `requestParameters.ruleAction` to "allow", and `requestParameters.portRange.to` - `requestParameters.portRange.from` > 1024.
5. The attacker associates the modified or newly created ACL with one or more subnets within the VPC.
6. The attacker attempts to connect to resources within the protected subnets using various protocols and ports to validate access.
7. Upon successful connection, the attacker can access and exfiltrate data, deploy malicious code, or disrupt services within the targeted subnets.

## Impact

A successful attack exploiting an overly permissive Network ACL can lead to unrestricted access to systems and data within the affected AWS subnets. This could result in data breaches, service disruption, or the deployment of ransomware. The number of affected resources depends on the scope of the ACL and the number of subnets it protects. The impact can range from a single compromised EC2 instance to a complete compromise of the AWS environment.

## Recommendation

*   Deploy the Sigma rule `AWS Network ACL Created with All Open Ports` to your SIEM and tune for your environment to detect the creation of overly permissive ACLs.
*   Enable AWS CloudTrail logging for all regions in your AWS account to ensure complete visibility into API activity (AWS CloudTrail CreateNetworkAclEntry, AWS CloudTrail ReplaceNetworkAclEntry).
*   Implement infrastructure-as-code (IaC) practices and automated validation to prevent the creation of overly permissive ACLs.
*   Regularly review existing Network ACLs to identify and remediate any overly permissive rules.
*   Enforce the principle of least privilege when configuring Network ACLs, granting access only to the required ports and protocols.
