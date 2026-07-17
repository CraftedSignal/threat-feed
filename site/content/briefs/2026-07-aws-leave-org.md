---
title: AWS Attempt to Leave Organization
slug: 2026-07-aws-leave-org
description: An adversary attempting to remove an AWS member account from its AWS Organization via the LeaveOrganization API constitutes a critical defense evasion maneuver, as it strips the account of security controls and centralized monitoring, requiring immediate investigation by detection engineers.
date: "2026-07-17T07:43:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - defense-evasion
  - impact
  - threat-detection
vendors:
  - Amazon
products:
  - AWS Organizations
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Leaving an organization immediately strips the account of every Service Control Policy (SCP) guardrail the organization enforces, removes it from centralized CloudTrail aggregation, and eliminates the management account's ability to audit or control it going forward.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Leaving an organization immediately strips the account of every Service Control Policy (SCP) guardrail the organization enforces, removes it from centralized CloudTrail aggregation, and eliminates the management account's ability to audit or control it going forward.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/organizations/latest/APIReference/API_LeaveOrganization.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.organizations-leave/
rules:
  - title: AWS Attempt to Leave Organization
    description: Detects any attempt, successful or denied, for a member account to leave an AWS Organization via the LeaveOrganization API. This action strips the account of security controls and monitoring.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1531
      - T1562
      - T1562.001
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Adversaries with root or organization-management-capable access within an AWS member account may leverage the `LeaveOrganization` API call to escape an AWS Organization's security controls and monitoring. This action, detected regardless of success, signifies a significant defense evasion attempt. Upon successfully leaving an organization, the account is immediately stripped of all Service Control Policies (SCPs), is removed from centralized CloudTrail aggregation, and loses oversight from the management account. This allows the attacker to operate unmonitored and execute further malicious actions without the organizational guardrails. The Elastic detection rule, created in July 2026, aims to identify these critical events, whether successful or denied, as both indicate malicious intent and a potential compromise.

## Attack Chain

1. An adversary gains initial access to an AWS member account, obtaining root credentials or credentials with explicit `organizations:LeaveOrganization` permissions.
2. The adversary conducts reconnaissance to understand the account's organizational context and identifies the `LeaveOrganization` API as a method to bypass organizational security.
3. Using the compromised credentials, the adversary invokes the `organizations:LeaveOrganization` API call from the target member account.
4. The AWS Organizations service processes the request to remove the account from the organization.
5. If authorized, the account is successfully removed from the AWS Organization, becoming an independent AWS account.
6. All Service Control Policies (SCPs) previously enforced by the parent organization are immediately de-applied from the now-independent account.
7. Centralized CloudTrail aggregation, GuardDuty, Security Hub, and other organizational monitoring mechanisms cease to receive logs or alerts from the departed account.
8. The management account loses its ability to audit or control the now-independent member account, providing the adversary with a less monitored environment for further malicious activity.

## Impact

A successful attempt to leave an AWS Organization allows an adversary to operate largely unmonitored and without the security guardrails of the organization. This removes Service Control Policies (SCPs), which are critical for enforcing security standards across all member accounts, potentially enabling unapproved resource creation or configuration changes. Centralized CloudTrail logging, GuardDuty, and Security Hub aggregation will cease for the departed account, severely hindering incident response capabilities and visibility into the adversary's subsequent actions. The management account loses its ability to audit or control the compromised account, making it extremely difficult to detect and remediate ongoing threats. While no specific victim counts are provided, this technique impacts the organizational security posture directly, affecting all resources within the compromised account.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM and tune for your environment to detect attempts to leave an AWS Organization.
* Monitor `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` in your AWS CloudTrail logs to identify the principal attempting the `LeaveOrganization` action.
* Review the `event.outcome` field in AWS CloudTrail logs. If `success`, treat the account as compromised and re-invite it to the organization using `InviteAccountToOrganization`.
* Investigate `source.ip`, `user_agent.original`, and `source.geo` associated with `LeaveOrganization` events for anomalies.
* Correlate `LeaveOrganization` events with other defense evasion or persistence activities, such as recent IAM changes or root login events, identified through AWS CloudTrail logs.
