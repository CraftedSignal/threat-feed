---
title: AWS SAML Provider Deletion Activity
slug: 2024-12-19-aws-saml-provider-deletion
description: An adversary may delete an AWS SAML provider to disrupt administrative access, hindering incident response and potentially escalating privileges within the AWS environment.
date: "2024-12-19T00:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - saml
  - iam
  - deletion
  - impact
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1531
    technique_name: Account Access Removal
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteSAMLProvider.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_delete_saml_provider.yml
rules:
  - title: AWS SAML Provider Deletion Activity
    description: Detects the deletion of an AWS SAML provider, potentially indicating malicious intent to disrupt administrative or security team access.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
      - T1531
    data_sources:
      - aws
      - cloudtrail
  - title: AWS SAML Provider Deletion Attempt (Failed)
    description: Detects a failed attempt to delete an AWS SAML provider, potentially indicating reconnaissance or unauthorized activity.
    platform: sigma
    severity: low
    tactics:
      - impact
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
      - T1531
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The deletion of a SAML provider in AWS can be a significant indicator of malicious activity. An attacker who has gained initial access to an AWS environment may attempt to remove the SAML provider used by the information security team or system administrators. This action can severely impede the team's ability to investigate and respond to ongoing attacks. By disrupting access, the attacker gains a window of opportunity to further escalate privileges, move laterally within the environment, and achieve their objectives without immediate detection or intervention. This activity directly impacts the availability and integrity of resources within the AWS cloud environment.

## Attack Chain

1.  Initial access is gained to an AWS account through compromised credentials or other means (T1078.004).
2.  The attacker enumerates existing IAM resources, including SAML providers, using AWS CLI or API calls.
3.  The attacker identifies the SAML provider used by administrative or security teams.
4.  The attacker executes the `DeleteSAMLProvider` API call via the AWS CLI, API, or AWS Management Console (T1531).
5.  The `DeleteSAMLProvider` event is logged in AWS CloudTrail with a "success" status.
6.  Administrative and security teams lose access to AWS resources that require SAML authentication.
7.  The attacker leverages the compromised account to escalate privileges, create new IAM users, or modify existing policies.
8.  The attacker persists in the environment, potentially exfiltrating data or deploying malicious workloads (T1485).

## Impact

The deletion of an AWS SAML provider can have serious consequences. It disrupts access for administrators and security personnel, delaying incident response and potentially allowing attackers to further compromise the environment. This can lead to data breaches, service disruptions, and financial losses. The severity of the impact depends on the criticality of the affected AWS resources and the speed of detection and recovery.

## Recommendation

*   Deploy the Sigma rule "AWS SAML Provider Deletion Activity" to your SIEM and tune for your environment to detect this specific event.
*   Investigate any `DeleteSAMLProvider` events in AWS CloudTrail, focusing on the user identity, user agent, and source IP address (logsource: aws/cloudtrail).
*   Implement multi-factor authentication (MFA) for all IAM users, especially those with administrative privileges, to reduce the risk of credential compromise (T1110).
*   Review and enforce the principle of least privilege for all IAM roles and users to limit the impact of compromised credentials.
