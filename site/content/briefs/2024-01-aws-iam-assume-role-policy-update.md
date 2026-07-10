---
title: AWS IAM Assume Role Policy Update
slug: 2024-01-aws-iam-assume-role-policy-update
description: An attacker modifies an AWS IAM role's trust policy to gain the privileges of the role, potentially leading to privilege escalation and persistence within the AWS environment.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - iam
  - privilege-escalation
  - persistence
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_iam_update_assume_role_policy.toml
  - https://labs.bishopfox.com/tech-blog/5-privesc-attack-vectors-in-aws
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/003/
  - https://attack.mitre.org/tactics/TA0004/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: AWS IAM Assume Role Policy Updated
    description: Detects when an IAM role's assume role policy is updated, potentially indicating privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1078.004
      - T1098
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS IAM Role Trust Policy Modified by Unusual User Agent
    description: Detects modifications to the IAM Role trust policy by unusual User Agents
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1078.004
      - T1098
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

The AWS IAM Assume Role Policy Update involves an attacker modifying the trust policy of an IAM role. The trust policy, a JSON document, dictates which principals can assume the role. By altering this policy, a malicious actor can grant themselves or other unauthorized entities the ability to assume the role and inherit its associated privileges. This allows for privilege escalation, persistence, and lateral movement within the AWS environment. This activity is detected via CloudTrail logs monitoring `UpdateAssumeRolePolicy` events. Successfully modifying the trust policy could have a wide-ranging impact depending on the permissions associated with the targeted role. This activity is often observed as part of broader attempts to establish persistence or elevate privileges within a compromised AWS environment. The Elastic detection rule was last updated on 2026/04/10.

## Attack Chain

1.  Initial Access: The attacker gains initial access to an AWS account, possibly through compromised credentials or an exploited vulnerability.
2.  Discovery: The attacker enumerates existing IAM roles and their associated trust policies to identify potential targets for privilege escalation.
3.  Policy Modification: The attacker uses the `UpdateAssumeRolePolicy` API call to modify the trust policy of a chosen IAM role. The attacker adds a malicious principal (e.g., a compromised user or role) to the policy.
4.  Privilege Escalation: The attacker assumes the targeted IAM role, gaining the permissions associated with that role.
5.  Lateral Movement: The attacker leverages the newly acquired permissions to access other AWS resources or services.
6.  Persistence: The attacker modifies other IAM roles or resources using the compromised role, ensuring continued access even if the initial access vector is closed.
7.  Data Exfiltration or Damage: The attacker uses the escalated privileges to exfiltrate sensitive data or cause damage to AWS resources.

## Impact

A successful IAM role trust policy update can grant an attacker significant control over the AWS environment. The scope of the impact depends on the privileges associated with the compromised role. This could lead to data breaches, service disruptions, or unauthorized access to critical systems. While the rule is classified as "low" severity, the consequences of successful exploitation can be severe, potentially affecting all aspects of the cloud infrastructure and data stored within. There is no mention of the number of victims or impacted sectors in the provided source material.

## Recommendation

*   Deploy the Sigma rule provided below to detect suspicious `UpdateAssumeRolePolicy` events in AWS CloudTrail logs.
*   Review `aws.cloudtrail.request_parameters` in CloudTrail logs when the Sigma rule triggers to examine the modifications made to the trust policy.
*   Investigate the IAM user or assumed role (`aws.cloudtrail.user_identity.arn`) that initiated the `UpdateAssumeRolePolicy` event for any anomalous activity.
*   Monitor CloudTrail logs for events associated with the compromised IAM role (`entity.target.id`) following the trust policy update.
*   Implement the AWS security best practices outlined in the provided reference to minimize the attack surface and potential impact.
