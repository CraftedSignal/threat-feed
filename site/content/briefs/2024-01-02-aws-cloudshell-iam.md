---
title: AWS IAM Operations via Compromised CloudShell
slug: 2024-01-02-aws-cloudshell-iam
description: Compromised AWS console sessions can lead to attackers performing sensitive IAM operations via CloudShell to establish persistence or escalate privileges.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloudshell
  - aws
  - iam
  - persistence
  - privilege-escalation
vendors:
  - AWS
products:
  - AWS CloudShell
  - AWS Management Console
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/cloudshell/latest/userguide/welcome.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
rules:
  - title: AWS IAM Operations via CloudShell
    description: Detects sensitive AWS IAM operations performed via AWS CloudShell based on the user agent string, indicating potential post-compromise activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1136
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Role Policy Attachment via CloudShell
    description: Detects AWS IAM role policy attachments performed via AWS CloudShell, indicating potential privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

AWS CloudShell is a browser-based shell environment that allows command-line access to AWS resources directly from the AWS Management Console. While it offers convenience for administrators, it also presents a risk if an attacker gains access to a compromised console session. An attacker can leverage CloudShell to perform sensitive operations, such as creating IAM users, access keys, and roles, or attaching policies, without the need to install any tools or utilize programmatic credentials. This activity can be indicative of post-compromise credential harvesting or privilege escalation activity within the AWS environment. Defenders should monitor for unusual IAM activity originating from CloudShell sessions, particularly those involving the creation or modification of identities and permissions.

## Attack Chain

1. An attacker gains unauthorized access to an AWS Management Console session, potentially through credential theft or session hijacking.
2. The attacker launches AWS CloudShell from within the compromised console session. This provides a command-line interface to the AWS environment.
3. Using the CloudShell environment, the attacker attempts to create a new IAM user with elevated privileges using the `aws iam create-user` command.
4. The attacker generates a new access key for the newly created IAM user or an existing compromised user with the `aws iam create-access-key` command.
5. The attacker creates a new IAM role with overly permissive policies attached using the `aws iam create-role` command.
6. The attacker attaches policies to existing IAM users or roles using the `aws iam attach-user-policy` or `aws iam attach-role-policy` commands to escalate privileges.
7. The attacker leverages the newly created or modified IAM identities and access keys to persist in the AWS environment and perform lateral movement.
8. The final objective is to maintain persistent access to the AWS environment, escalate privileges, and potentially exfiltrate sensitive data or cause disruption.

## Impact

Successful exploitation can lead to unauthorized access to sensitive AWS resources, data exfiltration, and service disruption. Attackers may create persistent backdoors within the AWS environment through the creation of rogue IAM users or roles. The number of victims depends on the scope of the compromised AWS account. Industries that heavily rely on AWS infrastructure are particularly vulnerable.

## Recommendation

*   Deploy the Sigma rule `AWS IAM Operations via CloudShell` to your SIEM and tune for your environment to detect suspicious IAM activity originating from CloudShell sessions.
*   Implement session duration limits for AWS Management Console sessions to reduce the window of opportunity for console session abuse.
*   Review and restrict CloudShell access via SCPs or IAM policies for sensitive accounts.
*   Investigate any `ConsoleLogin` events followed by IAM actions from CloudShell as described in the rule's description.
