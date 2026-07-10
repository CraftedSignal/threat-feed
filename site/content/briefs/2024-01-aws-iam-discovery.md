---
title: AWS IAM Access Denied Discovery Events
slug: 2024-01-aws-iam-discovery
description: This detection identifies potential reconnaissance activity by an attacker attempting to discover AWS IAM permissions and configurations by generating a high volume of access denied events.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - iam
  - reconnaissance
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1589
    technique_name: Gather Victim Identity Information
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_iam_accessdenied_discovery_events.yml
rules:
  - title: Detect High Volume of AWS IAM Access Denied Events
    description: Detects a high volume of AWS IAM Access Denied events, indicating potential reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1589
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS IAM Access Denied Events from Uncommon User Agent
    description: Detects AWS IAM Access Denied events originating from uncommon User Agents, possibly indicating attacker tools.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1589
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection focuses on identifying potential reconnaissance efforts within an AWS environment. An attacker might attempt to enumerate AWS IAM configurations, roles, and permissions to identify potential targets for privilege escalation or lateral movement. This activity generates a large number of "access denied" events in AWS CloudTrail logs, indicating that the attacker is probing the environment to understand what actions are permitted and what resources are accessible. Successful detection of this activity can help defenders identify and stop attackers before they gain a foothold in the AWS environment. The activity is detected through analysis of AWS CloudTrail logs.

## Attack Chain

1.  Attacker gains initial access to an AWS environment through compromised credentials or an exposed API key.
2.  The attacker attempts to list all IAM users within the AWS account using the `iam:ListUsers` API call. This generates an "access denied" event if the attacker does not have the necessary permissions.
3.  The attacker attempts to enumerate all IAM roles within the AWS account using the `iam:ListRoles` API call. This also results in "access denied" events if permissions are lacking.
4.  The attacker tries to read the policies attached to specific IAM users by calling `iam:GetUserPolicy` for various user names. This probes for directly attached user policies.
5.  The attacker attempts to determine which roles a user can assume using the `sts:AssumeRole` API call with different role ARNs, again creating access denied events for unauthorized attempts.
6.  The attacker probes for service-linked roles using `iam:GetServiceLinkedRoleDeletionStatus` on multiple service names.
7.  The attacker aggregates the "access denied" responses to build a map of accessible vs. inaccessible resources and actions within the AWS environment.
8.  The attacker uses the discovered information to refine their attack strategy, focusing on exploiting accessible resources or attempting privilege escalation.

## Impact

Successful discovery of AWS IAM configurations allows an attacker to map out the permissions landscape of the AWS environment. This enables them to identify potential privilege escalation paths, discover vulnerable resources, and ultimately compromise critical systems or data. Undetected IAM discovery can lead to data breaches, service disruptions, and significant financial losses. The scope of the impact depends on the level of access the attacker eventually gains and the criticality of the compromised resources.
