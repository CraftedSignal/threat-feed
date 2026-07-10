---
title: AWS Login Profile Creation Activity
slug: 2024-01-aws-login-profile-creation
description: Monitoring AWS login profile creation events can help identify potentially malicious user or role creation activities within an AWS environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - cloud
  - privilege-escalation
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_createloginprofile.yml
rules:
  - title: AWS CreateLoginProfile API Call
    description: Detects calls to the AWS CreateLoginProfile API, which can indicate user creation or modification activity.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CreateLoginProfile API Call from Uncommon Source IP
    description: Detects calls to the AWS CreateLoginProfile API from source IPs not usually associated with administrative activity.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The creation of AWS login profiles is a fundamental administrative action, but it can also be exploited by malicious actors to establish persistent access or escalate privileges within an AWS environment. Monitoring these events allows security teams to detect suspicious or unauthorized activities related to user and role management. Understanding who is creating these profiles and under what circumstances can provide valuable insights into the security posture of the AWS environment. This activity is important for defenders to monitor, as attackers will attempt to persist and escalate privileges in the cloud environment to conduct further attacks.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or a misconfigured IAM role (T1078).
2.  The attacker leverages existing AWS CLI or SDK tools to interact with the AWS environment.
3.  The attacker calls the `CreateLoginProfile` API to create a new user login profile using the compromised or misused credentials or role (T1098).
4.  The attacker configures password policies or other settings for the newly created user, ensuring continued access (T1543).
5.  The newly created user is then used to perform reconnaissance activities, such as listing resources, identifying sensitive data stores, or mapping network configurations.
6.  Privilege escalation is attempted by assigning the new user to groups or roles with broader permissions.
7.  Sensitive data is accessed, exfiltrated, or manipulated using the newly escalated privileges (TA0009).

## Impact

Successful exploitation via unauthorized login profile creation can lead to significant data breaches, service disruption, and reputational damage. The impact ranges from unauthorized access to sensitive data and resources to the complete compromise of the AWS environment, depending on the permissions granted to the newly created or modified user accounts.
