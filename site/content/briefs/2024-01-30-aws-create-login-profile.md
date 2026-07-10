---
title: AWS CreateLoginProfile Activity Detection
slug: 2024-01-30-aws-create-login-profile
description: Detects the creation of AWS IAM login profiles, which can be indicative of new user creation or modifications by potentially malicious actors for privilege escalation or persistence.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - iam
  - privilege_escalation
  - persistence
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_createloginprofile.yml
rules:
  - title: AWS CreateLoginProfile Activity
    description: Detects the creation of an AWS IAM Login Profile, which can indicate suspicious user creation or modification.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CreateLoginProfile by Root Account
    description: Detects CreateLoginProfile events performed by the AWS root account, which is highly unusual and often indicative of compromise.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on detecting the creation of AWS IAM login profiles. While the source material provides limited context, the action itself—creating a login profile—can be a signal of interest. Attackers may create new IAM users or modify existing ones (creating login profiles if they don't exist) to establish persistence, escalate privileges, or move laterally within an AWS environment. Defenders should monitor these activities closely, especially if they deviate from established baselines or involve suspicious actors. The `aws_createloginprofile.yml` file suggests a detection rule exists within Splunk's security content framework to identify this behavior. Monitoring for this event can help identify potentially malicious activity in AWS environments.

## Attack Chain

1. **Initial Compromise:** (Assumed) The attacker gains initial access to an AWS account, possibly through compromised credentials or an exposed API key (Not documented in source).
2. **Privilege Escalation:** The attacker attempts to escalate their privileges within the AWS environment, either through exploiting misconfigurations or leveraging existing IAM roles (Not documented in source).
3. **IAM Manipulation:** The attacker interacts with the AWS IAM service, specifically targeting user management (Observed - CreateLoginProfile).
4. **Create Login Profile:** The attacker uses the `CreateLoginProfile` API call to create a login profile for a new or existing IAM user. This provides the user with console access, enabling interactive login.
5. **Persistence:** The attacker leverages the newly created user with console access as a means of persistence within the AWS environment.
6. **Lateral Movement:** The attacker uses the new or modified user to access other AWS resources or services, expanding their control within the environment.
7. **Data Exfiltration / Damage:** (Assumed) The attacker utilizes their access to exfiltrate sensitive data or cause damage to the AWS infrastructure. (Not documented in source).

## Impact

The successful creation of a login profile by a malicious actor can lead to unauthorized access to AWS resources, data breaches, and service disruption. Attackers may use these profiles to maintain persistence, escalate privileges, and move laterally within the AWS environment. The number of victims depends on the scope of the attacker's access and the sensitivity of the compromised resources.

## Recommendation

*   Deploy the Sigma rule for `AWS CreateLoginProfile Activity` to your SIEM and tune for your environment (Reference: `aws_createloginprofile.yml`).
*   Investigate any instances of `CreateLoginProfile` events, especially those performed by unfamiliar IAM entities, to validate legitimacy.
*   Monitor AWS CloudTrail logs for `CreateLoginProfile` events to ensure comprehensive visibility into IAM activity.
*   Enforce multi-factor authentication (MFA) for all IAM users to reduce the risk of credential compromise (General Security Best Practice).
