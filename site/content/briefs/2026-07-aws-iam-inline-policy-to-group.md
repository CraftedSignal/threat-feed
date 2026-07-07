---
title: AWS IAM Inline Policy Added to a Group
slug: 2026-07-aws-iam-inline-policy-to-group
description: Adversaries can escalate privileges and establish persistence within AWS by leveraging the `PutGroupPolicy` API call to attach an inline policy to an IAM group, granting broad permissions to all group members, including themselves.
date: "2026-07-03T15:53:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - privilege-escalation
  - persistence
  - identity
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries can abuse this to escalate privileges (grant elevated permissions to a group they belong to, or will add themselves to).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries can abuse this... to establish persistence through a durable, membership-based grant that is easy to overlook.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutGroupPolicy.html
rules:
  - title: AWS IAM Inline Policy Added to a Group
    description: Detects the addition of an inline policy to an IAM group via PutGroupPolicy, a common technique for privilege escalation or persistence in AWS environments. This rule filters out common automation tools.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

This threat brief focuses on the malicious use of the `PutGroupPolicy` API in Amazon Web Services (AWS) Identity and Access Management (IAM). Adversaries who gain initial access to an AWS environment may exploit this functionality to escalate their privileges or establish persistence. By embedding an inline permissions policy directly onto an IAM group, attackers can grant elevated permissions to every current and future member of that group. This method is particularly effective for broad privilege grants, as it applies to all group members. The creation of inline policies on groups is a relatively uncommon administrative practice compared to attaching managed policies, making its occurrence by an unexpected principal a strong indicator of malicious activity and a valuable detection signal. This technique can be used to secure or expand access within a compromised AWS account, making it critical for defenders to monitor.

## Attack Chain

1.  **Initial Access**: An attacker obtains valid AWS credentials through various means (e.g., compromised access keys, stolen session tokens, vulnerable web application exploitation leading to metadata endpoint access).
2.  **Privilege Enumeration**: The attacker identifies IAM users, roles, or groups that they have permissions to modify, specifically looking for principals with `iam:PutGroupPolicy` permissions.
3.  **Target Group Identification**: The attacker identifies an existing IAM group, or creates a new one, to which they or their controlled identities belong, or can be added.
4.  **Malicious Policy Crafting**: The attacker constructs an IAM inline policy document containing broad or specific elevated permissions (e.g., `s3:*`, `ec2:*`, `iam:*` actions on `Resource: "*"`) designed for privilege escalation or persistence.
5.  **Policy Attachment**: The attacker invokes the `PutGroupPolicy` API call, associating the crafted malicious policy with the target IAM group.
6.  **Privilege Escalation/Persistence Achieved**: Upon successful attachment, all members of the target IAM group, including the attacker's compromised identity, immediately inherit the permissions defined in the malicious inline policy.
7.  **Post-Exploitation Activity**: The attacker utilizes these newly acquired elevated permissions to achieve their ultimate objective, such as data exfiltration, resource manipulation, service disruption, or further lateral movement within the AWS environment.

## Impact

The successful exploitation of this technique can lead to severe consequences, including widespread privilege escalation and persistence across an AWS account. Since an inline policy attached to a group grants its permissions to all current and future group members, an attacker can quickly provide themselves or other compromised accounts with elevated access to critical AWS resources. This can result in unauthorized access to sensitive data (e.g., S3 buckets, databases), control over computing resources (e.g., EC2 instances, Lambda functions), and the ability to modify security configurations, potentially leading to significant financial loss, data breaches, and operational disruption. The subtle nature of inline policies compared to well-known managed policies can make detection and remediation more challenging.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect unauthorized `PutGroupPolicy` actions.
*   Restrict `iam:PutGroupPolicy` permissions to a minimal set of trusted administrative roles or automation systems.
*   Regularly review all `PutGroupPolicy` activity in your AWS CloudTrail logs to identify suspicious inline policy attachments.
*   Inspect the `aws.cloudtrail.request_parameters.policyDocument` field within detected events for broad permissions (`Action: "*"`, `Resource: "*"`) or specific sensitive actions.
*   Rotate credentials for any principal (`aws.cloudtrail.user_identity.arn`) suspected of unauthorized `PutGroupPolicy` activity.
