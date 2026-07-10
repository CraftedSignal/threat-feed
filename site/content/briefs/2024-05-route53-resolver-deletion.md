---
title: AWS Route 53 Resolver Query Log Configuration Deleted
slug: 2024-05-route53-resolver-deletion
description: Detection of the deletion of an Amazon Route 53 Resolver Query Log Configuration, potentially stopping DNS query and response logging for associated VPCs, which can be used by adversaries to evade detection and suppress forensic evidence.
date: "2024-05-14T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - route53
  - defense_evasion
vendors:
  - AWS
products:
  - AWS Route 53 Resolver
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_DeleteResolverQueryLogConfig.html
rules:
  - title: AWS Route 53 Resolver Query Log Configuration Deleted
    description: Detects the deletion of an Amazon Route 53 Resolver Query Log Configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Route53 Resolver Query Log Config Deletion by Unusual User
    description: Detects Route53 Resolver Query Log Config Deletion by a user that doesn't usually modify Route53 Resolver resources
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Amazon Route 53 Resolver query logs offer crucial insights into DNS activity across VPCs, encompassing lookups from EC2 instances, containers, and Lambda functions. The deletion of a query log configuration immediately halts DNS query and response logging for the associated VPC, creating a monitoring gap. This activity is often associated with defense evasion, where attackers attempt to remove logging to obscure their actions. This detection identifies successful invocations of the `DeleteResolverQueryLogConfig` API call within AWS CloudTrail logs. The scope of impact can range from individual VPCs to entire AWS environments, depending on the breadth of the deleted configuration. Defenders should prioritize investigation to determine whether the deletion was authorized and to identify potential malicious activity that may have been obscured.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account with sufficient privileges.
2. The attacker uses compromised credentials or an IAM role to interact with the AWS Management Console, CLI, or SDK.
3. The attacker identifies a Route 53 Resolver Query Log Configuration that is actively logging DNS queries for one or more VPCs.
4. The attacker invokes the `DeleteResolverQueryLogConfig` API call, specifying the ID of the target query log configuration.
5. AWS CloudTrail logs the `DeleteResolverQueryLogConfig` event with a successful outcome.
6. DNS query and response logging immediately ceases for the VPCs associated with the deleted configuration.
7. The attacker performs malicious activities, such as DNS tunneling or command and control communication, without being logged.
8. The attacker achieves their final objective, such as data exfiltration or system compromise, without detection via DNS logs.

## Impact

A successful attack can lead to a significant reduction in DNS visibility across affected VPCs. Depending on the scope, this can impact a few resources or an entire AWS environment. The immediate consequence is the cessation of DNS query logging, which can obscure ongoing malicious activity, such as command-and-control communication, data exfiltration attempts, or reconnaissance efforts. The lack of DNS data hinders incident response and forensic investigations, making it difficult to identify the scope and impact of the attack.

## Recommendation

*   Deploy the Sigma rule `AWS Route 53 Resolver Query Log Configuration Deleted` to your SIEM and tune for your environment.
*   Review IAM permissions and restrict the `route53resolver:DeleteResolverQueryLogConfig` action to a minimal set of privileged roles.
*   Enable AWS Config rules to detect and alert on missing or deleted Route 53 Resolver Query Log Configurations.
*   Investigate any deletion of Resolver Query Log Configurations to determine if it was authorized and corresponds to expected operational changes.
*   Monitor `aws.cloudtrail.user_identity.arn` for any unusual IAM roles or user accounts performing the deletion action as identified in the Sigma rule.
*   Re-create the deleted Resolver Query Log Configuration and re-associate it with the affected VPCs to restore DNS visibility immediately.
