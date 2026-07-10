---
title: Detection of New User AWS Console Login
slug: 2024-01-02-aws-new-console-login
description: A new AWS user logging into the console could indicate malicious activity, such as an attacker creating a new identity for persistence or lateral movement within the AWS environment.
date: "2024-01-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - iam
  - initial_access
vendors:
  - Amazon
products:
  - Amazon Web Services
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_aws_console_login_by_new_user.yml
rules:
  - title: Detect First Time AWS Console Login
    description: Detects an AWS user logging into the console for the first time.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS IAM User Creation
    description: Detects the creation of a new IAM user in AWS.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Detecting when a new user logs into the AWS console for the first time is a critical security measure. While legitimate user onboarding happens regularly, malicious actors may create new AWS identities to establish persistence, escalate privileges, or move laterally within a compromised environment. This activity, if unauthorized, can lead to significant data breaches, service disruption, and financial loss. By monitoring initial console logins, security teams can rapidly identify and investigate potentially malicious activity, preventing further damage. Early detection is key to containing the impact of a compromised AWS environment.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to an AWS account through compromised credentials or an exposed IAM role.
2.  **Privilege Escalation:** The attacker attempts to escalate their privileges using existing IAM roles or policies.
3.  **IAM User Creation:** The attacker creates a new IAM user with elevated privileges to ensure persistent access.
4.  **Console Login:** The attacker uses the newly created IAM user credentials to log into the AWS Management Console.
5.  **Resource Enumeration:** The attacker enumerates AWS resources, such as EC2 instances, S3 buckets, and databases, to identify valuable targets.
6.  **Data Exfiltration/Manipulation:** Depending on their objective, the attacker exfiltrates sensitive data from S3 buckets or databases, or manipulates AWS resources to cause disruption or financial damage.

## Impact

Compromised AWS environments can lead to severe consequences, including unauthorized access to sensitive data, service disruptions, and financial losses. Data breaches resulting from compromised AWS accounts can expose customer data, intellectual property, and other confidential information. Service disruptions can impact business operations and damage reputation. Financial losses can result from unauthorized resource consumption or malicious activities.

## Recommendation

*   Implement the provided Sigma rule to detect first-time AWS console logins to your SIEM and tune for your environment.
*   Investigate any alerts triggered by the Sigma rule to determine if the console login is legitimate or malicious.
*   Review IAM policies and roles to ensure least privilege and prevent unauthorized privilege escalation.
