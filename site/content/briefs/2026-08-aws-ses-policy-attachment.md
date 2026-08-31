---
title: Unusual Attachment of AmazonSESFullAccess Policy in AWS
slug: 2026-08-aws-ses-policy-attachment
description: Threat actors may attach the AmazonSESFullAccess policy to IAM entities to establish phishing infrastructure and send emails using a victim organization's verified domain.
date: "2026-08-31T17:52:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - resource-development
  - aws
  - iam
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS SES
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Granting this policy to an unexpected IAM entity, particularly a newly created user or a role not previously associated with email operations, is a documented technique used by threat actors to establish phishing infrastructure.
    confidence_band: high
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1608
    technique_name: Stage Capabilities
    evidence: Threat actors who compromise an AWS account often establish phishing infrastructure by granting SES access to a new or existing IAM identity.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html
rules:
  - title: Detect AWS SES Full Access Policy Attachment by Unusual Caller
    description: Detects when the AmazonSESFullAccess policy is attached to an IAM user, role, or group by an identity that has not performed this action in the last 7 days.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1098.003
      - T1608
    data_sources:
      - process_creation
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy new_terms rule for SES policy attachment monitoring.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for AmazonSESFullAccess policy monitoring.
  hunt_leads:
    - lead: Identify all existing IAM identities with AmazonSESFullAccess attached.
      technique_id: T1098.003
      data_needed:
        - IAM policy assignment data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Establishing SES control is a primary objective for attackers.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict AmazonSESFullAccess policy assignment to least-privilege roles.
      owner: Cloud Security
      addresses: T1098.003
      evidence: Granting this policy to an unexpected IAM entity enables unauthorized email infrastructure.
---

Threat actors who gain unauthorized access to an AWS environment may attach the AmazonSESFullAccess managed policy to an IAM entity, such as a user, role, or group. This managed policy provides unrestricted permissions to perform sensitive SES actions, including sending emails, verifying new email identities, managing suppression lists, and modifying account-level sending settings. 

This activity is commonly observed as a means for attackers to build phishing infrastructure within a compromised cloud environment. By granting these permissions, an attacker can leverage the victim organization's trusted, verified sending domain to send bulk phishing emails, significantly increasing the probability of successful social engineering campaigns. Defenders should prioritize alerting on first-time or unusual associations of this policy, as routine email automation services may legitimately perform these attachments.

## Attack Chain

1. Attacker gains initial access to an AWS environment via compromised IAM credentials or an insecure identity.
2. Attacker performs discovery to identify existing IAM users, roles, or groups for potential escalation.
3. Attacker evaluates the permissions of the current identity to determine if they can attach managed policies (iam:AttachUserPolicy, iam:AttachRolePolicy, or iam:AttachGroupPolicy).
4. Attacker attaches the AmazonSESFullAccess policy to a controlled IAM entity to gain full SES control.
5. Attacker verifies SES account sending status via iam:GetAccountSendingEnabled.
6. Attacker uses ses:VerifyEmailIdentity or ses:SetIdentityMailFromDomain to establish control over malicious sending domains.
7. Attacker proceeds to execute mass phishing campaigns via ses:SendEmail or ses:SendRawEmail while utilizing the victim's domain reputation.

## Impact

The primary impact is the unauthorized use of the organization's verified domain reputation to distribute phishing content. This can lead to domain blacklisting, reputational damage, and increased exposure for employees and partners who receive the fraudulent emails. Additionally, if an attacker modifies the account's suppression list or sending settings, they can disrupt legitimate business communications and bypass security controls.

## Recommendation

- Monitor AWS CloudTrail management events for the AmazonSESFullAccess policy attachment to any IAM entity.
- Establish a baseline of identities authorized to modify IAM policies and SES configurations; investigate any deviations from this baseline.
- Review SES account sending status and current identity verifications after any unauthorized IAM policy changes.
- Implement the detection rule below to surface first-time policy attachments by specific calling identities.
- Rotate credentials for any IAM identity involved in unauthorized policy modification or SES activity.
