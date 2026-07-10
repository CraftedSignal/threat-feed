---
title: AWS Login Profile Creation Followed by Console Login
slug: 2024-01-03-aws-create-login-profile
description: Detection of an AWS user creating a login profile for another user, followed by a console login from the same source IP, potentially indicating privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - privilege-escalation
  - persistence
vendors:
  - AWS
products:
  - AWS CloudTrail
  - AWS IAM
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://bishopfox.com/blog/privilege-escalation-in-aws
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
rules:
  - title: AWS CreateLoginProfile Followed by ConsoleLogin
    description: Detects the creation of a login profile followed by a console login from the same source IP, potentially indicating privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CreateLoginProfile Event
    description: Detects the CreateLoginProfile event in AWS CloudTrail.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic detects a potential privilege escalation attack in AWS environments. It focuses on the creation of a login profile for one AWS user by another, immediately followed by a console login from the same source IP address. The detection utilizes AWS CloudTrail logs to correlate the `CreateLoginProfile` and `ConsoleLogin` events based on the source IP and user identity. This activity is considered suspicious because it could signify an attacker attempting to escalate privileges by creating a new login profile for themselves or another account to gain unauthorized access. Successful exploitation enables the attacker to maintain persistence and move laterally within the AWS environment. The original Splunk ES-CU rule was published in April 2026, indicating the enduring relevance of this threat.

## Attack Chain

1. An attacker gains initial access to an AWS account with sufficient privileges.
2. The attacker uses their compromised credentials to execute the `CreateLoginProfile` API call.
3. The `CreateLoginProfile` call creates a new login profile for a target user account.
4. The attacker attempts to log into the AWS Management Console using the newly created login profile.
5. A `ConsoleLogin` event is generated, associated with the new login profile.
6. The AWS CloudTrail logs record both the `CreateLoginProfile` and the subsequent `ConsoleLogin` events, including the source IP address.
7. The attacker leverages the new access to enumerate AWS resources.
8. The attacker escalates privileges and moves laterally, potentially deploying malicious workloads or exfiltrating sensitive data.

## Impact

Successful exploitation allows an attacker to escalate privileges within the AWS environment and maintain persistent access. This can lead to unauthorized access to sensitive data, deployment of malicious workloads, disruption of services, and potential data exfiltration. The severity of the impact depends on the privileges associated with the compromised accounts and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule provided to detect `CreateLoginProfile` events followed by `ConsoleLogin` events from the same source IP address (Sigma rule).
*   Investigate any detected instances of login profile creation followed by console login, paying close attention to the user identities and source IP addresses involved (AWS CloudTrail logs).
*   Review and enforce least privilege principles to minimize the impact of potential privilege escalation attacks (AWS IAM documentation).
*   Monitor AWS CloudTrail logs for suspicious API calls and login activity (AWS CloudTrail logs).
