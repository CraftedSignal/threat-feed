---
title: AWS IAM Persistence via User Session Token
slug: 2024-01-aws-iam-session-token-persistence
description: This brief covers detection of potential persistence techniques in AWS environments through the use of compromised user session tokens to make IAM API calls, potentially leading to unauthorized privilege escalation or resource access.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - persistence
  - cloud
vendors:
  - AWS
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_api_calls_via_user_session_token.toml
rules:
  - title: Detect IAM Policy Changes via User Session Token
    description: Detects changes to IAM policies made using a user session token, which could indicate persistence attempts.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.004
    data_sources:
      - cloudtrail
      - aws
  - title: Detect IAM Role Modification via User Session Token
    description: Detects modifications to IAM Roles, which may indicate a persistence attempt by an attacker
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the potential misuse of AWS IAM user session tokens to establish persistence within an AWS environment. While the specific campaign details are not available in the provided source, the detection rule's focus on IAM API calls suggests a scenario where an attacker has gained access to a valid user session token. This token could then be used to make unauthorized changes to IAM policies, roles, or users, effectively creating backdoors for persistent access. The absence of campaign details necessitates a proactive detection strategy centered on suspicious IAM API activity originating from user session tokens. This is critical for defenders as successful persistence can lead to long-term data breaches, resource hijacking, and reputational damage.

## Attack Chain

1.  **Initial Access:** Attacker gains access to a valid AWS IAM user session token through unknown means (e.g., credential theft, phishing, or compromised systems).
2.  **Token Validation:** Attacker validates the compromised token by making a benign AWS API call (e.g., `sts:GetCallerIdentity`) to confirm its validity and associated IAM role/user.
3.  **Privilege Assessment:** Attacker enumerates existing IAM policies, roles, and users using AWS API calls like `iam:ListRoles`, `iam:ListUsers`, and `iam:ListPolicies` to identify potential targets for persistence.
4.  **Policy Modification (Persistence):** The attacker modifies existing IAM policies or creates new ones with overly permissive rights using API calls like `iam:UpdateRole`, `iam:CreatePolicy`, or `iam:PutRolePolicy`. This grants persistent access to resources.
5.  **Role Assumption:** The attacker creates or modifies IAM roles with trust policies that allow the attacker's controlled entities (e.g., EC2 instances, Lambda functions) to assume those roles using `sts:AssumeRole`.
6.  **User Modification:** The attacker modifies existing IAM users by adding new access keys or changing passwords. API calls like `iam:CreateAccessKey` or `iam:UpdateLoginProfile` are used.
7.  **Backdoor Creation:** The attacker might create new IAM users with specific credentials that they control using `iam:CreateUser`.
8.  **Persistent Access & Lateral Movement:** Using the newly established persistent access, the attacker moves laterally within the AWS environment, accessing resources and data as needed.

## Impact

Compromised AWS IAM user session tokens can lead to significant security breaches. Attackers can establish persistent access to AWS environments, bypassing normal authentication mechanisms. This can result in unauthorized access to sensitive data, modification or deletion of critical resources, and ultimately, significant financial and reputational damage. The number of potential victims is vast, encompassing any organization relying on AWS for its infrastructure and services.

## Recommendation

*   Deploy the Sigma rule "Detect IAM Policy Changes via User Session Token" to your SIEM to identify suspicious IAM policy modifications (rule provided below).
*   Enable AWS CloudTrail logging for all AWS regions and services to capture detailed API activity, providing the necessary data source for the Sigma rule.
*   Implement multi-factor authentication (MFA) for all IAM users to reduce the risk of token compromise.
*   Regularly review IAM policies and roles for overly permissive permissions and implement the principle of least privilege.
