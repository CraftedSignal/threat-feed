---
title: AWS Sensitive IAM Operations Performed via CloudShell
slug: 2026-07-aws-cloudshell-iam-operations
description: Attackers can leverage a compromised AWS console session to perform sensitive AWS IAM operations via AWS CloudShell, establishing persistence or escalating privileges, which can be detected by monitoring CloudTrail logs for specific user agent strings and high-risk IAM actions.
date: "2026-07-15T14:24:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - privilege-escalation
vendors:
  - AWS
products:
  - AWS CloudShell
  - AWS Management Console
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This rule detects high-risk actions such as creating IAM users, access keys, roles, or attaching policies when initiated from CloudShell, which may indicate post-compromise credential harvesting or privilege escalation activity.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: This rule detects high-risk actions such as creating IAM users, access keys, roles, or attaching policies when initiated from CloudShell.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This rule detects high-risk actions such as creating IAM users, access keys, roles, or attaching policies when initiated from CloudShell, which may indicate post-compromise credential harvesting or privilege escalation activity.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This rule detects high-risk actions such as creating IAM users, access keys, roles, or attaching policies when initiated from CloudShell, which may indicate post-compromise credential harvesting or privilege escalation activity.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/cloudshell/latest/userguide/welcome.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
rules:
  - title: AWS Sensitive IAM Operations Performed via CloudShell
    description: Detects sensitive AWS IAM operations (creating users, access keys, roles, or attaching policies) when performed via AWS CloudShell, indicating potential post-compromise persistence or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.001
      - T1098.003
      - T1136
      - T1136.003
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

This threat brief details the detection of sensitive AWS Identity and Access Management (IAM) operations executed through AWS CloudShell. AWS CloudShell provides convenient, browser-based command-line access to AWS resources directly from the AWS Management Console, eliminating the need for local CLI installations or credential configurations. While useful for legitimate administrators, this capability becomes a significant risk if an AWS Management Console session is compromised. Attackers can exploit CloudShell access to perform high-risk actions - such as creating IAM users, access keys, roles, or attaching policies - without leaving forensic artifacts on their local systems or requiring programmatic credentials. These activities are indicative of post-compromise credential harvesting, privilege escalation, or persistence establishment. Detection relies on monitoring AWS CloudTrail logs for specific IAM actions combined with the `CloudShell` user agent string, which signals unauthorized modifications within the AWS environment.

## Attack Chain

1. **Initial Access**: An attacker gains unauthorized access to an AWS Management Console session, typically through stolen credentials, session hijacking, or successful phishing campaigns.
2. **CloudShell Launch**: From the compromised AWS Management Console, the attacker navigates to and launches AWS CloudShell, leveraging its integrated command-line environment.
3. **IAM Command Execution**: The attacker uses the CloudShell terminal to execute AWS IAM commands, aiming to create new identities or modify existing permissions.
4. **Credential Creation**: The attacker creates new IAM users (e.g., `CreateUser`), generates new access keys for existing users (e.g., `CreateAccessKey`), or creates new IAM roles (e.g., `CreateRole`) to establish alternative access points.
5. **Policy Attachment/Modification**: The attacker attaches new or existing policies (e.g., `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`) to users or roles to grant them expanded or unrestricted permissions.
6. **Persistence/Privilege Escalation**: Through these IAM manipulations, the attacker establishes persistent access mechanisms or escalates privileges within the AWS environment, ensuring continued unauthorized access even if the initial console session is revoked.
7. **Resource Exploitation**: With elevated privileges, the attacker proceeds to access, modify, exfiltrate sensitive data, or disrupt critical AWS resources and services.

## Impact

Successful exploitation of compromised AWS Management Console sessions via CloudShell can lead to severe consequences. Attackers can establish persistent backdoor access, escalate privileges to gain control over critical AWS resources, and compromise data integrity and confidentiality. The creation of unauthorized users or access keys allows for ongoing unauthorized access, potentially leading to widespread data exfiltration, resource manipulation, service disruption, and significant financial loss due to unauthorized resource usage. These actions directly undermine the security posture of the AWS account, making it difficult to detect and evict the attacker without a thorough incident response.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM to detect suspicious IAM operations originating from AWS CloudShell.
* Configure AWS CloudTrail logging to capture all management events for your AWS account, which is the log source for this detection.
* Review `aws.cloudtrail.user_identity.arn`, `source.ip`, and `source.geo` fields in CloudTrail logs to identify the actor and verify the request origin for any CloudShell-initiated IAM changes.
* Implement AWS Identity and Access Management (IAM) policies or Service Control Policies (SCPs) to restrict CloudShell access for sensitive accounts or to limit the types of IAM operations that can be performed via CloudShell.
* Establish a baseline of normal CloudShell usage patterns within your organization to reduce false positives by identifying and allowing legitimate administrative workflows.
* For any unauthorized activity, immediately terminate the compromised console session and revoke any created credentials.
