---
title: AWS STS Role Chaining for Privilege Escalation and Persistence
slug: 2024-10-aws-sts-role-chaining
description: AWS STS role chaining, where one assumed role is used to assume another, can lead to privilege escalation or persistence by refreshing session tokens, triggering alerts on the first observed role assumption based on CloudTrail logs.
date: "2024-10-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - sts
  - role-chaining
  - privilege-escalation
  - persistence
vendors:
  - AWS
products:
  - AWS Security Token Service
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#id_roles_terms-and-concepts
  - https://www.uptycs.com/blog/detecting-anomalous-aws-sessions-temporary-credentials
  - https://hackingthe.cloud/aws/post_exploitation/role-chain-juggling/
rules:
  - title: Detect AWS STS Role Chaining
    description: Detects AWS STS role chaining by identifying AssumeRole events where the user identity type is AssumedRole, indicating that the caller is another role.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cross-Account AWS STS Role Chaining
    description: Detects AWS STS role chaining across different AWS accounts by identifying AssumeRole events where the recipient account ID differs from the resources account ID.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the potential abuse of AWS STS role chaining. Role chaining is a legitimate AWS feature where an assumed role is used to assume another role through the AWS CLI or API. However, malicious actors can exploit this functionality to escalate privileges if the second assumed role has broader permissions than the initial role. The chaining can also be used as a persistence mechanism since each `AssumeRole` action results in a refreshed session token with a maximum duration of one hour. This activity is detected by monitoring CloudTrail logs for the first occurrence of a role (identified by `aws.cloudtrail.user_identity.session_context.session_issuer.arn`) assuming another role (`aws.cloudtrail.resources.arn`). Detection focuses on identifying novel role-chaining relationships to highlight potentially unauthorized activity.

## Attack Chain

1. An attacker gains initial access to an AWS account, possibly through compromised credentials or an exposed access key.
2. The attacker uses the compromised credentials to assume an initial IAM role using `sts:AssumeRole`. This action is logged in CloudTrail with the `AssumeRole` event.
3. The attacker then uses the temporary credentials obtained from the first role to assume a second IAM role, again using `sts:AssumeRole`. The `aws.cloudtrail.user_identity.session_context.session_issuer.arn` field identifies the first role, and the `aws.cloudtrail.resources.arn` field identifies the second role.
4. If the second role has more permissions than the first, the attacker can use the second role's credentials to perform actions they couldn't do before (privilege escalation). This could involve actions related to IAM, EC2, S3 or other AWS services.
5. The attacker leverages the increased permissions to access sensitive data stored in S3 buckets, modify IAM policies to grant themselves further access, or launch EC2 instances for malicious purposes.
6. Each AssumeRole action generates new temporary credentials, effectively refreshing the attacker's session.
7. The attacker maintains persistence within the AWS environment by repeatedly chaining roles to refresh temporary credentials.
8. The attacker achieves their objective, such as exfiltrating sensitive data, deploying malware, or disrupting services.

## Impact

Successful exploitation via role chaining can lead to significant privilege escalation within an AWS environment. This can enable attackers to gain unauthorized access to sensitive data, modify critical infrastructure configurations, and potentially disrupt business operations. The persistence aspect of role chaining can allow attackers to maintain a foothold in the environment for extended periods, making detection and remediation more challenging. The blast radius can extend across multiple AWS accounts if cross-account role chaining is involved.

## Recommendation

*   Deploy the Sigma rule `Detect AWS STS Role Chaining` to identify instances of role chaining in AWS CloudTrail logs. Tune the rule to exclude expected role-chaining patterns based on your environment (`aws.cloudtrail.user_identity.session_context.session_issuer.arn`, `aws.cloudtrail.resources.arn`).
*   Monitor CloudTrail logs for `AssumeRole` events where `aws.cloudtrail.user_identity.type` is `AssumedRole`, focusing on unusual or unexpected role combinations.
*   Implement least privilege policies for all IAM roles, limiting trust policies to only required principals. Periodically review role chaining patterns to validate necessity.
*   Use the `AWS STS Role Chaining` Sigma rule to identify potential role chaining attempts and investigate accordingly.
*   Correlate CloudTrail logs with other security events (e.g., GuardDuty alerts) to identify potential privilege escalation or data exfiltration activities following role chaining.
*   Enable MFA where possible on `AssumeRole` operations.
