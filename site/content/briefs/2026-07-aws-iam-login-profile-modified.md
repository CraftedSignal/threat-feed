---
title: AWS IAM Login Profile Created or Modified for an IAM User
slug: 2026-07-aws-iam-login-profile-modified
description: This rule detects the creation or modification of console login profiles for AWS IAM users via the CreateLoginProfile or UpdateLoginProfile APIs. Adversaries with stolen programmatic credentials can use these actions to establish persistent interactive console access, reset other users' passwords to take over accounts, and maintain access even after original access keys are rotated. Since IAM user console access is increasingly managed through federation or IAM Identity Center, direct use of these APIs, especially by unexpected principals, warrants investigation as a strong indicator of persistence or account compromise.
date: "2026-07-03T15:50:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - persistence
  - identity
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries who obtain programmatic credentials may create a login profile to add persistent interactive console access, or update an existing profile to reset another user's password and take over the account, even after the original access keys are rotated.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateLoginProfile.html
rules:
  - title: AWS IAM Login Profile Created or Modified for IAM User
    description: Detects the creation or modification of a console login profile for an AWS IAM user via CreateLoginProfile or UpdateLoginProfile APIs, which adversaries can use for persistence and account takeover.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
      - T1098.001
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Adversaries who have obtained programmatic AWS credentials are leveraging the `CreateLoginProfile` and `UpdateLoginProfile` APIs to establish persistent access within compromised AWS environments. This activity, identified as a key persistence technique, allows attackers to either create new password-based console access for an IAM user who previously lacked it, or to reset an existing IAM user's console password, effectively taking over the account. This tactic enables continued access even if the initial compromised access keys are rotated or invalidated, providing a durable foothold. Given that modern AWS console access for IAM users is predominantly managed through federated identity or IAM Identity Center, direct invocation of these APIs by unexpected or unapproved principals is a significant indicator of potential compromise, warranting immediate investigation. This activity has been observed as a post-compromise action to escalate privileges and maintain access.

## Attack Chain

1.  Adversary gains programmatic access to an AWS environment (e.g., via compromised access keys, assumed role credentials, or misconfigured IAM policies).
2.  Using the compromised programmatic credentials, the adversary calls the `iam:CreateLoginProfile` API operation, providing a `userName` and a new `password` for an existing IAM user who lacks a console login profile.
3.  Alternatively, the adversary calls the `iam:UpdateLoginProfile` API operation, providing a `userName` and a new `password` to reset the console password of an existing IAM user's login profile.
4.  The AWS API call successfully creates or updates the login profile with the adversary-controlled password, recorded as an `eventStatus: "Success"` in CloudTrail.
5.  The adversary then uses the newly set or reset password to authenticate and log in to the AWS Management Console as the targeted IAM user.
6.  This action establishes persistent interactive console access for the adversary, allowing them to perform actions as the compromised IAM user and potentially exfiltrate data, provision resources, or further escalate privileges.

## Impact

Successful exploitation of this persistence technique grants adversaries interactive console access to the AWS environment under the guise of a legitimate IAM user. This can lead to full account takeover, enabling unauthorized data exfiltration, resource manipulation, privilege escalation, or disruption of cloud services. The ability to reset passwords means attackers can maintain access even after the initial compromised programmatic credentials are revoked, making remediation more challenging. The overall impact includes potential financial loss, operational disruption, and reputational damage due to sustained unauthorized access to critical cloud infrastructure.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, especially the "AWS IAM Login Profile Created or Modified for IAM User" rule.
*   Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.request_parameters` fields for events matching the Sigma rule to identify the acting principal and targeted user, correlating with expected administrative activities.
*   Ensure AWS CloudTrail logging is enabled for all regions and ingested into your SIEM to activate the detection logic in this brief.
*   Restrict `iam:CreateLoginProfile` and `iam:UpdateLoginProfile` permissions to a very small, trusted set of administrative roles, preferring federation or IAM Identity Center for console access, as suggested in the rule's false positives.
*   If unauthorized activity is confirmed by the "AWS IAM Login Profile Created or Modified for IAM User" rule, delete the affected login profile or reset the user's password, and revoke any active console sessions for that user immediately.
