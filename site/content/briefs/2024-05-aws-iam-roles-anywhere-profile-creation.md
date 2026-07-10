---
title: AWS IAM Roles Anywhere Profile Creation
slug: 2024-05-aws-iam-roles-anywhere-profile-creation
description: Detection of AWS IAM Roles Anywhere profile creation, potentially indicating an adversary establishing persistence or escalating privileges through rogue trust anchors to gain long-term external access.
date: "2024-05-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - iam
  - rolesanywhere
  - persistence
  - privilege-escalation
vendors:
  - AWS
products:
  - IAM Roles Anywhere
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
  - https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-iam-roles-anywhere-trust-anchor-created/
  - https://ermetic.com/blog/aws/keep-your-iam-users-close-keep-your-third-parties-even-closer-part-1/
  - https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_CreateProfile.html
rules:
  - title: AWS IAM Roles Anywhere Profile Creation
    description: Detects the creation of a new AWS IAM Roles Anywhere profile.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Roles Anywhere Profile Creation by Unusual Identity
    description: Detects the creation of a new AWS IAM Roles Anywhere profile by an identity not typically associated with IAM management.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

AWS IAM Roles Anywhere enables external workloads to assume IAM roles securely, using certificates from trusted anchors. A profile links IAM roles to trust anchors and defines session duration. This detection identifies the "CreateProfile" API call, which adversaries may use to create or modify profiles, linking them with highly privileged roles or unauthorized trust anchors. This allows for long-term external access to the AWS environment. The rule focuses on successful 'CreateProfile' API calls. It is important to monitor profile creation to ensure that only approved roles and trust anchors are in use. This activity can lead to persistence and privilege escalation.

## Attack Chain

1.  The adversary compromises an external system or obtains unauthorized access to a trusted certificate authority.
2.  The adversary establishes a rogue trust anchor within AWS IAM Roles Anywhere, representing the compromised CA or external system.
3.  The attacker leverages the `CreateProfile` API call to create a new IAM Roles Anywhere profile.
4.  The profile is configured to associate the rogue trust anchor with one or more IAM roles. The `roleArns` parameter within the `request_parameters` should be closely monitored for excessive permissions.
5.  The adversary sets a long `durationSeconds` for the profile, maximizing the window of opportunity for assuming roles.
6.  The attacker uses the `AssumeRoleWithCertificate` API call, presenting a valid certificate issued by the compromised CA, to assume an IAM role associated with the newly created profile.
7.  The assumed role is then used to perform unauthorized actions within the AWS environment, such as accessing sensitive data, modifying infrastructure, or deploying malicious code.
8.  The adversary maintains persistent access to the AWS environment through the compromised trust anchor and associated profile, enabling long-term control.

## Impact

Successful exploitation can grant unauthorized external access to the AWS environment. This may lead to data breaches, service disruption, or the deployment of malicious infrastructure. While the source provides no specific numbers, the impact depends on the privileges associated with the assumed roles and the extent of the adversary's lateral movement within the AWS environment. Compromised Roles Anywhere profiles can provide persistent access, making detection and remediation critical.

## Recommendation

*   Deploy the Sigma rule `AWS IAM Roles Anywhere Profile Creation` to your SIEM and tune for your environment to detect unauthorized profile creation events.
*   Restrict `rolesanywhere:CreateProfile` API calls to a small set of administrative roles within your AWS environment to prevent unauthorized profile creation.
*   Implement AWS Config or Security Hub controls to alert on unauthorized or overly permissive Roles Anywhere profiles, as mentioned in the overview section.
*   Review IAM role trust policies linked to external anchors, ensuring adherence to the principle of least privilege to minimize the impact of compromised profiles.
