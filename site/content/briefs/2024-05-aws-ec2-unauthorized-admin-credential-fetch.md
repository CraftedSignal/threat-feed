---
title: AWS EC2 Unauthorized Admin Credential Fetch via Assumed Role
slug: 2024-05-aws-ec2-unauthorized-admin-credential-fetch
description: The rule detects the first occurrence of an unauthorized attempt by an AWS role to use `GetPasswordData` to access the administrator password of an EC2 instance, potentially indicating privilege escalation or lateral movement.
date: "2024-05-02T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - credential-access
vendors:
  - AWS
products:
  - EC2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc
rules:
  - title: AWS EC2 Unauthorized Admin Credential Fetch
    description: Detects unauthorized GetPasswordData API calls from assumed roles in AWS EC2
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078.004
      - T1552.005
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 GetPasswordData Success by Assumed Role
    description: Detects successful GetPasswordData API calls from assumed roles in AWS EC2.
    platform: sigma
    severity: informational
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies unauthorized attempts to retrieve EC2 instance administrator passwords using the AWS `GetPasswordData` API call. The rule focuses on detecting unusual use of this API call by roles that have not been seen making this request within the last 7 days, leveraging the "new_terms" functionality. The primary goal is to detect potential privilege escalation or lateral movement attempts by adversaries who have compromised an AWS role. This activity is often part of a larger attack aimed at gaining broader access to cloud resources. The rule is designed to trigger on the first occurrence of such unauthorized activity, providing early warning of potential security breaches within the AWS environment. It is crucial for defenders to quickly identify and respond to these attempts to prevent further compromise of EC2 instances.

## Attack Chain

1. An attacker compromises an AWS Identity and Access Management (IAM) role, possibly through exposed credentials or exploiting a vulnerability in an application with IAM permissions.
2. The attacker uses the compromised IAM role to authenticate to the AWS environment and enumerate EC2 instances.
3. The attacker attempts to retrieve the administrator password for an EC2 instance using the `GetPasswordData` API call.
4. AWS CloudTrail logs the API call, including details about the user identity, session context, and request parameters.
5. The detection rule identifies the `GetPasswordData` API call with an `Client.UnauthorizedOperation` error code.
6. The detection logic checks if the assumed role's ARN (`aws.cloudtrail.user_identity.session_context.session_issuer.arn`) has been seen making this API request in the last 7 days.
7. If the role is new to this activity, the rule triggers, indicating a potential unauthorized attempt to access EC2 instance credentials.
8. If successful, the attacker uses the retrieved administrator password to log in to the EC2 instance, gaining control and potentially escalating privileges further.

## Impact

A successful attack could lead to unauthorized access to sensitive data stored on the EC2 instance, disruption of services, or further lateral movement within the AWS environment. Compromised EC2 instances can be used to launch attacks against other systems or to exfiltrate sensitive information. The impact can range from data breaches and financial loss to reputational damage, depending on the criticality of the compromised EC2 instances. This type of attack can affect organizations across various sectors that rely on AWS for their infrastructure.

## Recommendation

*   Deploy the Sigma rule "AWS EC2 Unauthorized Admin Credential Fetch" to your SIEM and tune for your environment.
*   Review the permissions of the implicated user identity (`aws.cloudtrail.user_identity.arn`) and apply the principle of least privilege to prevent misuse.
*   Investigate the origin of the API call by analyzing the IP address (`source.address`) and geographical location to determine if it aligns with expected administrative activity.
*   Enable enhanced monitoring on the user identity that triggered the rule and similar EC2 instances to detect future unauthorized activity.
*   Refer to resources like [AWS privilege escalation methods](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc) for mitigation strategies.
