---
title: AWS Root Account Persistence via CreateLoginProfile
slug: 2026-09-aws-root-login-persistence
description: Adversaries with temporary root access may invoke the CreateLoginProfile API without a username to establish persistent console password access for the AWS root principal.
date: "2026-09-18T19:38:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - aws
  - cloud
  - identity-and-access-audit
vendors:
  - Amazon
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries who have gained temporary root-level access in an AWS environment may use the CreateLoginProfile API call.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This grants persistent access even if the attacker's API keys are later rotated or disabled.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_create_login_profile_for_root.toml
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
rules:
  - title: Detect AWS Root IAM Login Profile Creation
    description: Detects creation of a console login profile for the AWS account root user by checking for successful CreateLoginProfile events where the identity type is Root and no username is specified.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for root login profile creation.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific logic for detecting this persistence technique.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict iam:CreateLoginProfile permissions for all IAM users and roles.
      owner: IT Operations
      addresses: Account manipulation (T1098)
      evidence: Rule documentation notes this is a critical security incident.
---

Adversaries who obtain temporary elevated privileges in an AWS environment may attempt to establish long-term persistence by creating or resetting the console login profile for the root account. By executing the `CreateLoginProfile` API call while operating under a temporary root session (e.g., via `AssumeRoot`), and omitting the `userName` parameter, the attacker effectively assigns a password to the root user principal itself. This grants the attacker persistent administrative access to the AWS Management Console that remains valid even after the original temporary access keys or tokens used to gain entry are rotated, disabled, or expire. Because the root user possesses unrestricted privileges across the entire account, this activity represents a critical security incident necessitating immediate containment and credential rotation. Defenders should monitor for `CreateLoginProfile` events where the user identity is type 'Root' and the request parameters lack a specified username.

## Attack Chain

1. The attacker gains initial access to temporary AWS credentials through techniques such as phishing, compromised access keys, or insecure environment variables.
2. The attacker performs discovery to identify available privileges, eventually leveraging a method to assume a root or highly privileged session (e.g., `AssumeRoot`).
3. The attacker identifies that they have sufficient IAM permissions to perform administrative actions, specifically `iam:CreateLoginProfile`.
4. The attacker executes the `CreateLoginProfile` API call against the AWS IAM endpoint.
5. The attacker omits the `userName` parameter in the request, causing AWS to apply the login profile to the root user.
6. The attacker sets a known password for the root account, effectively establishing a persistent entry point.
7. The attacker authenticates to the AWS Management Console using the newly created root password to maintain ongoing administrative access.

## Impact

Success in this attack provides the adversary with full, unrestricted administrative control over the entire AWS account. This allows for data exfiltration, resource destruction, the creation of additional backdoors, and the configuration of further persistence mechanisms. If undetected, this can lead to total account takeover, significant financial loss, and severe compliance violations.

## Recommendation

1. Deploy detection logic to monitor CloudTrail for `CreateLoginProfile` events initiated by the root user identity.
2. Correlate `CreateLoginProfile` activity with concurrent `AssumeRoot` or `ConsoleLogin` events to identify the session used for the modification.
3. Audit all IAM policies to enforce least-privilege, specifically restricting `iam:CreateLoginProfile` and `iam:UpdateLoginProfile` permissions to only essential personnel.
4. Ensure that MFA is enforced for all root-level access and verify that no root access keys are active.
5. If unauthorized modification is detected, immediately delete the login profile, rotate the root password, and invalidate all associated active sessions.
