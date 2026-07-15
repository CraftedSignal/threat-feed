---
title: Suspicious AWS STS AssumeRoot by Rare User and Member Account
slug: 2026-07-aws-sts-assumeroot-rare-user
description: Adversaries leveraging compromised user credentials can perform a suspicious AWS STS AssumeRoot action by a rarely observed user and member account combination to escalate privileges and gain unauthorized access to AWS resources, potentially leading to data exfiltration or resource manipulation.
date: "2026-07-15T14:27:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - aws-sts
  - privilege-escalation
  - cloud
  - aws
vendors:
  - Amazon Web Services
products:
  - AWS STS
  - AWS CloudTrail
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries who have compromised user credentials can use this technique to escalate privileges and gain unauthorized access to AWS resources.
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: AWS STS AssumeRoot issues temporary credentials that grant elevated access into a member account, constrained by the task policy and target policy attached to the request.
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: 'Look for high-impact actions such as: IAM changes (iam:CreateUser, iam:AttachRolePolicy, iam:PutRolePolicy, iam:UpdateAssumeRolePolicy).'
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries who have compromised user credentials can use this technique to escalate privileges and gain unauthorized access to AWS resources.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_sts_assume_root_from_rare_user_and_member_account.toml
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS STS AssumeRoot by Rare User and Member Account
    description: Detects when the STS AssumeRoot action is successfully performed by a user that rarely assumes this role against a specific member account, potentially indicating privilege escalation or unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1098.003
      - T1548.005
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

This brief details the detection of suspicious `AssumeRoot` actions within Amazon Web Services (AWS) environments, a technique adversaries exploit for privilege escalation. When attacker-compromised user credentials are used to invoke the `AssumeRoot` action, it allows them to temporarily assume the root member account role, granting elevated access to specified AWS resources. This particular detection focuses on identifying instances where this action is performed by a user or principal that rarely assumes this role, or against a member account that is not typically targeted by that principal. Such activity can signify privilege escalation, lateral movement into new accounts, or the abuse of cross-account access paths, posing a significant risk of unauthorized access, data compromise, and resource manipulation within the AWS infrastructure.

## Impact

A successful `AssumeRoot` action by an unauthorized entity grants them temporary but highly privileged access to the targeted AWS member account. This can lead to a wide array of damaging outcomes, including the creation of persistent backdoors via IAM changes (e.g., creating new users, modifying roles), disabling security controls like CloudTrail or GuardDuty to evade detection, or directly manipulating and exfiltrating sensitive data from services like S3, RDS, or DynamoDB. The blast radius can be significant, affecting core infrastructure, intellectual property, and customer data. Without timely detection and response, such an incident can result in severe financial loss, regulatory penalties, and reputational damage for the victim organization.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious `AssumeRoot` actions.
* Ensure comprehensive AWS CloudTrail logging is enabled for all `sts.amazonaws.com` events, which is the log source for this detection.
* When an alert fires, immediately investigate the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.resources.account_id` fields to identify the calling principal and the affected member account.
* Examine `source.address`, `source.geo.*`, and `user_agent.original` fields within the CloudTrail logs to understand the origin of the suspicious `AssumeRoot` call.
* Correlate follow-on activity by searching for subsequent events where `aws.cloudtrail.user_identity.access_key_id` matches the temporary credentials issued by the `AssumeRoot` event.
* Restrict `sts:AssumeRoot` usage by applying stringent IAM conditions, such as `aws:PrincipalArn` or `aws:PrincipalOrgID`, to limit which roles and identities can invoke this action.
