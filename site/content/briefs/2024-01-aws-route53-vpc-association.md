---
title: AWS Route 53 Private Hosted Zone Associated With Unauthorized VPC
slug: 2024-01-aws-route53-vpc-association
description: An adversary with sufficient permissions may associate unauthorized VPCs to intercept, observe, or reroute internal traffic, establish persistence, or expand their visibility within an AWS environment by associating a Route 53 private hosted zone with a new Virtual Private Cloud (VPC).
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - route53
  - persistence
vendors:
  - AWS
products:
  - Route 53
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583
    technique_name: Acquire Infrastructure
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_AssociateVPCWithHostedZone.html
rules:
  - title: AWS Route53 Hosted Zone VPC Association
    description: Detects when an AWS Route 53 hosted zone is associated with a VPC
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1098
      - T1583
    data_sources:
      - cloudtrail
      - aws
      - route53
  - title: AWS Route53 Hosted Zone VPC Association by Unusual User Agent
    description: Detects when an AWS Route 53 hosted zone is associated with a VPC by an unusual user agent
    platform: sigma
    severity: high
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1098
      - T1583
    data_sources:
      - cloudtrail
      - aws
      - route53
rules_count: 2
---

Attackers with sufficient AWS IAM permissions can associate a Route 53 private hosted zone with a Virtual Private Cloud (VPC) to expand the scope of internal DNS resolution, potentially intercepting, observing, or rerouting internal traffic. This activity allows adversaries to establish persistence or expand their visibility within an AWS environment. This association is achieved through the `AssociateVPCWithHostedZone` event. Defenders should monitor for unauthorized associations to prevent attackers from manipulating internal name resolution. The Elastic detection rule was last updated on April 10, 2026.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account, either through compromised credentials or exploiting a misconfigured IAM role, achieving initial access (TA0001).
2.  The attacker enumerates existing Route 53 hosted zones and associated VPCs to identify potential targets for manipulation.
3.  The attacker identifies a private hosted zone containing sensitive internal service records or privileged DNS information.
4.  The attacker creates or compromises a VPC within the AWS environment or cross-account.
5.  The attacker uses the `AssociateVPCWithHostedZone` API call to associate the attacker-controlled VPC with the targeted private hosted zone.
6.  The attacker modifies DNS records within the associated hosted zone to redirect traffic to attacker-controlled resources.
7.  The attacker intercepts internal traffic, observes service discovery processes, or redirects traffic to malicious services (TA0009).
8.  The attacker maintains persistent access by manipulating internal name resolution (TA0003).

## Impact

Successful exploitation allows attackers to intercept internal traffic, perform reconnaissance, and potentially gain access to sensitive data. The number of victims depends on the scope of the compromised hosted zone and the sensitivity of the data exposed. Targeted sectors could include any organization using AWS Route 53 for internal DNS resolution. If the attack succeeds, internal applications and services may become unavailable or compromised, leading to data breaches and service disruptions.

## Recommendation

*   Deploy the "AWS Route 53 Private Hosted Zone Associated With a VPC" Sigma rule to your SIEM and tune for your environment to detect unauthorized VPC associations.
*   Review `aws.cloudtrail.user_identity.arn` and `access_key_id` to identify the actor initiating the association, as mentioned in the investigation steps.
*   Limit `route53:AssociateVPCWithHostedZone` permissions to specific administrative roles and require MFA for privileged accounts.
*   Monitor AWS CloudTrail logs for `AssociateVPCWithHostedZone` events to identify suspicious activity.
