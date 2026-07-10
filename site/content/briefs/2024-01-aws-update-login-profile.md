---
title: AWS Account Login Profile Update
slug: 2024-01-aws-update-login-profile
description: An AWS account's login profile has been modified, potentially indicating account compromise, privilege escalation, or malicious user activity.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - iam
  - account-takeover
vendors:
  - Amazon
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_updateloginprofile.yml
rules:
  - title: Detect AWS UpdateLoginProfile from Unusual Source IP
    description: Detects UpdateLoginProfile calls from source IPs not usually associated with administrative activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1586
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS UpdateLoginProfile without MFA
    description: Detects UpdateLoginProfile calls where MFA was not used for authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1586
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS UpdateLoginProfile by a new or infrequent user
    description: Detects UpdateLoginProfile calls made by a previously unseen or infrequent user account
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1586
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

The UpdateLoginProfile API call in AWS allows modification of a user's password and password reset requirements. While legitimate administrator activity can trigger this event, it's also a potential indicator of malicious behavior. An attacker with compromised credentials or an insider threat could use this API call to change a user's password, lock them out of their account, and potentially escalate privileges or maintain persistence within the AWS environment. This activity is particularly concerning if MFA is not enforced, or if the user in question has elevated permissions.

## Attack Chain

1. An attacker gains initial access to an AWS account through compromised credentials, phishing, or other means.
2. The attacker enumerates existing IAM users to identify potential targets for account takeover.
3. The attacker calls the `UpdateLoginProfile` API, targeting a specific IAM user.
4. The attacker sets a new password for the targeted IAM user.
5. The attacker may optionally require the user to reset their password on the next login.
6. If successful, the attacker can now log in as the targeted user.
7. The attacker leverages the compromised account to access sensitive resources, launch attacks, or exfiltrate data.

## Impact

Successful exploitation could lead to unauthorized access to AWS resources, data breaches, privilege escalation, and disruption of services. The impact is dependent on the permissions associated with the compromised IAM user.

## Recommendation

*   Monitor AWS CloudTrail logs for `UpdateLoginProfile` events and deploy the Sigma rules to identify suspicious activity.
*   Investigate any instances of `UpdateLoginProfile` events that do not originate from authorized administrators (see rules).
*   Enforce multi-factor authentication (MFA) for all IAM users to mitigate the risk of credential compromise.
*   Implement strong password policies and regularly rotate passwords to reduce the effectiveness of brute-force attacks.
*   Review IAM user permissions and follow the principle of least privilege to minimize the impact of potential account compromise.
