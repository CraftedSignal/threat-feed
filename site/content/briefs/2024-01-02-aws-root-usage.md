---
title: AWS Root Account Usage Detected
slug: 2024-01-02-aws-root-usage
description: The AWS root account, which grants unrestricted access to all resources within an AWS account, was used, potentially indicating unauthorized activity, privilege escalation, or a breach of security best practices.
date: "2024-01-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - privilege-escalation
  - initial-access
  - persistence
  - stealth
vendors:
  - Amazon
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
rules:
  - title: AWS Root Account Login Without MFA
    description: Detects AWS root account login events without multi-factor authentication (MFA), which could indicate a compromised account.
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - aws
      - cloudtrail
  - title: AWS Root Account Usage
    description: Detects AWS root account usage for any API call, highlighting a potential security risk.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1078.004
    data_sources:
      - aws
      - cloudtrail
  - title: AWS Root Account Key Created
    description: Detects creation of an AWS root account access key.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - aws
      - cloudtrail
rules_count: 3
---

The use of the AWS root account should be strictly limited to specific tasks that cannot be performed with IAM users or roles. This alert indicates that the root account was used, which could signify various security concerns. An attacker with access to the root account can perform any action within the AWS environment, including creating new users, modifying security policies, accessing sensitive data, and deleting resources. Defenders should investigate each instance of root account usage to determine legitimacy. This activity may also indicate a misconfiguration where IAM roles should be used.

## Attack Chain

1.  An attacker gains access to the AWS root account credentials through credential theft or other means.
2.  The attacker authenticates to the AWS Management Console or uses the AWS CLI with the root account credentials.
3.  The attacker enumerates AWS resources to identify potential targets for privilege escalation.
4.  The attacker creates or modifies IAM policies to grant themselves additional permissions.
5.  The attacker may create new IAM users or roles with elevated privileges.
6.  The attacker uses the elevated privileges to access sensitive data stored in S3 buckets or other AWS services.
7.  The attacker modifies security configurations, such as network access control lists or security groups, to facilitate lateral movement or data exfiltration.
8.  The attacker could disable logging features to cover tracks.

## Impact

Compromise of the AWS root account can lead to a complete breach of the AWS environment, resulting in unauthorized access to sensitive data, data loss, service disruption, and potential financial losses. Attackers can leverage root privileges to perform nearly any action within the AWS account, affecting all services and resources. The number of affected victims depends on the scope and criticality of the AWS environment.

## Recommendation

*   Deploy the Sigma rule "AWS Root Credentials" to your SIEM to detect root account usage based on CloudTrail logs.
*   Investigate all instances of root account usage identified by the "AWS Root Credentials" Sigma rule to determine legitimacy.
*   Enforce multi-factor authentication (MFA) on all AWS accounts, including the root account, as documented in [AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html).
*   Implement the principle of least privilege by granting IAM users and roles only the permissions they need to perform their tasks.
*   Regularly audit IAM policies and user permissions to identify and remove unnecessary privileges.
*   Disable or restrict root account access wherever possible, delegating tasks to IAM users/roles.
