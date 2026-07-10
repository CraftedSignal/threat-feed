---
title: AWS IAM Assume Role Policy Brute Force Attack
slug: 2024-01-aws-iam-assume-role-brute-force
description: Detection of brute force attacks against AWS IAM roles by identifying multiple failed AssumeRole attempts using CloudTrail logs, potentially leading to unauthorized access and resource compromise.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - brute_force
  - cloudtrail
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1580
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/
  - https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/
  - https://www.elastic.co/guide/en/security/current/aws-iam-brute-force-of-assume-role-policy.html
rules:
  - title: AWS IAM Assume Role Brute Force Detection
    description: Detects potential brute force attacks against AWS IAM roles by identifying multiple failed AssumeRole attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1580
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
---

This detection focuses on identifying potential brute force attacks targeting AWS IAM roles. The attack involves adversaries attempting to guess valid role names in order to gain unauthorized access to AWS resources. By monitoring AWS CloudTrail logs for patterns of failed `AssumeRole` API calls, specifically those resulting in `MalformedPolicyDocumentException` errors, it is possible to identify suspicious activity indicative of a brute force attack. This analytic excludes known legitimate AWS service accounts to reduce false positives. The successful compromise of an IAM role can lead to privilege escalation, data exfiltration, and other malicious activities within the AWS environment. The detection is based on Amazon Security Lake events and requires ingesting CloudTrail logs.

## Attack Chain

1. **Initial Access:** The attacker attempts to assume an AWS IAM role using the `AssumeRole` API.
2. **Role Enumeration:** The attacker makes repeated `AssumeRole` requests, each time guessing a different role name.
3. **Access Denied:** Due to incorrect role names or policies, the `AssumeRole` requests fail, resulting in `MalformedPolicyDocumentException` errors with an `AccessDenied` status.
4. **CloudTrail Logging:** AWS CloudTrail logs each failed `AssumeRole` attempt, capturing details such as the user ID, source IP address, and API operation.
5. **Brute Force Threshold:** The attacker continues attempting different role names until a predefined threshold of failed attempts is reached (e.g., 3 failures within an hour).
6. **Successful AssumeRole (if applicable):** If the attacker successfully guesses a valid role name and satisfies the policy requirements, the `AssumeRole` API call succeeds, granting the attacker temporary credentials for the target role.
7. **Privilege Escalation:** The attacker uses the assumed role's credentials to access AWS resources and perform actions beyond their originally authorized permissions.
8. **Data Exfiltration / Resource Compromise:** Depending on the compromised role's permissions, the attacker may exfiltrate sensitive data, modify infrastructure configurations, or deploy malicious workloads.

## Impact

A successful IAM role brute force attack can lead to significant damage, including unauthorized access to sensitive data, modification or deletion of critical AWS resources, and potential disruption of business operations. The impact is highly dependent on the permissions associated with the compromised IAM role. If an attacker gains access to a role with broad privileges, the entire AWS environment could be at risk.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune for your environment, focusing on known good source IP ranges or trusted user groups (`actor.user.uid`) to reduce false positives.
*   Investigate users (`actor.user.uid`) triggering the detection, focusing on unusual source IP addresses (`src_endpoint.ip`) or user agents (`http_request.user_agent`).
*   Implement multi-factor authentication (MFA) for all IAM users to mitigate credential-based attacks.
*   Review and harden IAM role policies to limit the impact of successful role assumption.
*   Monitor CloudTrail logs for other suspicious API calls following a successful `AssumeRole` event.
*   Investigate the references provided for more information on AWS IAM Assume Role vulnerabilities.
