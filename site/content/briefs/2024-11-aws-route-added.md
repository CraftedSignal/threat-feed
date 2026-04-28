---
title: Detect AWS Route Table Modification via CloudTrail
slug: 2024-11-aws-route-added
description: An attacker may add a new route to an AWS route table, potentially redirecting network traffic for malicious purposes such as defense impairment or data exfiltration.
date: "2024-11-01T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - cloud
  - aws
  - network-routing
vendors:
  - Amazon
products:
  - AWS EC2
  - AWS CloudTrail
references:
  - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml
rules:
  - title: Detect AWS Route Table Modification via CloudTrail
    description: Detects the addition of a new network route to a route table in AWS.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
  - title: Detect Route Creation with Unusual Destination
    description: Detects route creation events with destination CIDR blocks outside the expected private IP ranges.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The addition of a new route to an AWS route table can be a sign of malicious activity, especially if the route redirects traffic to an unexpected or unauthorized destination. This activity is typically logged in AWS CloudTrail. Attackers might add routes to intercept network traffic, conduct man-in-the-middle attacks, or impair defenses by routing traffic away from security appliances. Understanding who is performing this action and the destination of the new route is critical for identifying potential threats within an AWS environment.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or an exploited vulnerability.
2. The attacker uses the AWS CLI or the AWS Management Console to interact with the EC2 service.
3. The attacker identifies the target route table to modify.
4. The attacker executes the `CreateRoute` API call, specifying the destination CIDR block and target (e.g., an internet gateway, virtual private gateway, or network interface).
5. CloudTrail logs the `CreateRoute` event, capturing details of the action, including the user identity, source IP address, and the route table modification.
6. Network traffic matching the new route's destination CIDR block is now redirected to the attacker-controlled target.
7. The attacker monitors and potentially modifies the redirected traffic for reconnaissance or data exfiltration purposes.

## Impact

Successful modification of AWS route tables can lead to significant security breaches. An attacker could redirect critical network traffic to a malicious endpoint, enabling them to intercept sensitive data or disrupt services. This could lead to data breaches, financial loss, and reputational damage. The scope of the impact depends on the criticality of the redirected traffic and the attacker's objectives.

## Recommendation

*   Deploy the "Detect AWS Route Table Modification via CloudTrail" Sigma rule to your SIEM and tune for your environment to detect suspicious route creation events in AWS CloudTrail logs.
*   Investigate any `CreateRoute` events where the user identity is unexpected or the destination CIDR block and target are suspicious.
*   Monitor AWS CloudTrail logs for `CreateRoute` events and correlate them with other suspicious activities.
*   Implement strict IAM policies to limit who can modify route tables (reference the `eventSource` and `eventName` fields in the rule below).
