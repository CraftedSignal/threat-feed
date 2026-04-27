---
title: AWS IAM Login Profile Added for Root
slug: 2024-12-aws-root-login-profile
description: An adversary with temporary root access in AWS may create a login profile for the root account to establish persistent console access, even if the original access keys are rotated or disabled.
date: "2026-04-10T16:27:52Z"
severities:
  - high
tags:
  - cloud
  - aws
  - iam
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_create_login_profile_for_root.toml
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/001/
  - https://attack.mitre.org/tactics/TA0003/
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
rules:
  - title: AWS IAM Login Profile Added for Root
    description: Detects creation of a console login profile for the AWS account root user.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CreateLoginProfile API call
    description: Detects CreateLoginProfile API call by any user
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule detects the creation of a console login profile for the AWS account root user, a highly privileged account. While `CreateLoginProfile` is normally applied to IAM users, when executed from a temporary root session (e.g., via `AssumeRoot`) without specifying a `userName`, the profile is created for the root principal. This activity is especially concerning because it provides persistent access. An attacker gaining temporary root access via STS or credential compromise might exploit this…
