---
title: AWS Console Login by New User
slug: 2024-01-aws-console-login-new-user
description: Detects first-time AWS console login, which can indicate compromised credentials or malicious account creation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - initial_access
vendors:
  - AWS
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_aws_console_login_by_new_user.yml
rules:
  - title: AWS Console Login By New User
    description: Detects first time AWS console login event for a user.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Console Login Without MFA
    description: Detects AWS console logins without MFA enabled.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the first-time login to the AWS console by a specific user. This is a critical monitoring point as it could indicate several security concerns. These include unauthorized access using compromised credentials, a malicious actor establishing a foothold in the AWS environment, or an insider threat creating new accounts for nefarious purposes. The detection focuses on identifying the initial console login event. It is crucial to investigate these events promptly to determine the legitimacy of the user activity. Early detection can prevent further malicious actions such as data exfiltration, resource exploitation, or privilege escalation. This detection is designed to work across all AWS environments and requires proper configuration of AWS CloudTrail.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account, possibly through credential theft or brute-forcing.
2.  The attacker logs into the AWS Management Console for the first time using the compromised or newly created account.
3.  The attacker explores the AWS environment to identify potential targets, resources, and vulnerabilities.
4.  The attacker attempts to escalate privileges by exploiting misconfigured IAM roles or policies.
5.  The attacker launches EC2 instances for cryptomining or other malicious purposes.
6.  The attacker accesses and exfiltrates sensitive data from S3 buckets or databases.
7.  The attacker covers their tracks by deleting CloudTrail logs or modifying security configurations.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, financial losses due to resource consumption (e.g., cryptomining), and reputational damage. A compromised AWS environment can be used to launch attacks against other targets, further amplifying the impact. The number of affected users and the extent of the damage depend on the level of access the attacker gains and the sensitivity of the data compromised. The financial impact can range from a few thousand dollars to millions, depending on the scale of the breach and the cost of remediation.
