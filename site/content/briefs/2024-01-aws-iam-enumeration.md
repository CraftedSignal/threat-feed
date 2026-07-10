---
title: AWS IAM Principal Enumeration via UpdateAssumeRolePolicy
slug: 2024-01-aws-iam-enumeration
description: Detects repeated failed attempts to update an IAM role's trust policy in an AWS account, consistent with role and user enumeration techniques, potentially indicating attacker-controlled infrastructure or offensive tooling.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - enumeration
  - discovery
  - credential-access
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities
  - https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/
rules:
  - title: AWS IAM Principal Enumeration - High Failure Count
    description: Detects a high number of failed UpdateAssumeRolePolicy calls, which is indicative of IAM principal enumeration attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1087.004
      - T1110
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM UpdateAssumeRolePolicy with Error
    description: Detects UpdateAssumeRolePolicy calls which result in a MalformedPolicyDocumentException.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069.003
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule identifies attempts to enumerate AWS IAM principals by detecting bursts of failed `UpdateAssumeRolePolicy` API calls. An attacker with valid AWS credentials might try to discover assumable roles or accounts by repeatedly modifying a role's trust relationship, guessing `Principal` ARNs. When invalid principals are specified, IAM rejects the request, generating a sequence of failed `UpdateAssumeRolePolicy` events with `MalformedPolicyDocumentException` errors. The rule triggers when the number of failures exceeds a defined threshold within a short period, suggesting a brute-force enumeration attempt rather than a legitimate misconfiguration. This activity might originate from compromised accounts, attacker-controlled infrastructure, or offensive security tools like Pacu, aiming to identify valid cross-account roles or users. The rule specifically focuses on detecting enumeration attempts originating from within the AWS account being monitored.

## Attack Chain

1.  Attacker gains initial access to an AWS account, potentially through compromised credentials or misconfigured roles.
2.  The attacker uses the acquired credentials to make repeated `UpdateAssumeRolePolicy` API calls on a target IAM role.
3.  Each `UpdateAssumeRolePolicy` call attempts to modify the role's trust policy with a different, potentially invalid, principal ARN.
4.  When the provided principal ARN is invalid, IAM returns a `MalformedPolicyDocumentException` error.
5.  The attacker iterates through a list of guessed cross-account role or user ARNs as the `Principal` in the `UpdateAssumeRolePolicy` requests.
6.  The attacker monitors the API responses for successful updates, indicating a valid principal ARN and a potential target for role assumption.
7.  Upon identifying a valid principal, the attacker may attempt to assume the target role using `AssumeRole` to gain elevated privileges.
8.  Successful role assumption allows the attacker to perform unauthorized actions within the targeted AWS account or service.

## Impact

Successful enumeration of IAM principals can lead to unauthorized access and privilege escalation within an AWS environment. An attacker might identify roles that grant access to sensitive data or critical services, leading to data breaches, service disruption, or infrastructure compromise. The number of victims and the extent of the damage depend on the permissions associated with the compromised roles and the attacker's objectives. The technique is often used as a reconnaissance step before more significant attacks, such as data exfiltration or resource destruction.

## Recommendation

*   Deploy the following Sigma rule to detect bursts of failed `UpdateAssumeRolePolicy` events indicative of IAM principal enumeration and tune the threshold value (`value: 25`) according to your environment's baseline activity.
*   Enable AWS CloudTrail logging to capture `UpdateAssumeRolePolicy` events and related IAM API calls (logsource: `aws.cloudtrail`).
*   Investigate alerts triggered by the Sigma rule by reviewing the `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields to determine the source and context of the failed attempts.
*   Limit permissions to modify trust policies (`iam:UpdateAssumeRolePolicy`) to a small set of administrative roles, following the principle of least privilege.
*   Monitor for reconnaissance-related API calls (`ListRoles`, `ListUsers`, `GetCallerIdentity`) before the threshold event to proactively identify potential enumeration attempts.
