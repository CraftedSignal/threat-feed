---
title: AWS Account Closure Detected
slug: 2026-07-aws-account-closed
description: Adversaries or malicious insiders may close an AWS account using the `CloseAccount` API, a highly destructive action that suspends all access for 90 days before permanent termination, leading to data destruction and significant business disruption.
date: "2026-07-17T07:26:01Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - cloud
  - aws
  - impact
  - data-destruction
  - account-access-removal
vendors:
  - Amazon Web Services
products:
  - AWS account
  - AWS Organizations
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Account closure triggers a 90-day grace period during which the account is suspended before permanent termination, removing access to all resources and data in the account for the duration of the suspension.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Account closure removes access to all resources and data in the account for the duration of the suspension.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/accounts/latest/reference/API_CloseAccount.html
  - https://docs.aws.amazon.com/organizations/latest/APIReference/API_CloseAccount.html
  - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_close.html
rules:
  - title: Detect AWS Account Closure via CloseAccount API
    description: Detects the closure of an AWS account via the CloseAccount API, a highly destructive action that suspends the account for 90 days before permanent termination.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
      - T1531
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

This threat brief details the critical impact of an AWS account closure, which can be initiated by an adversary who gains root credentials to an AWS account or management-level access to an AWS Organizations management account, or by a malicious insider. The `CloseAccount` API call, whether self-service (`account.amazonaws.com`) or initiated by an organization's management account (`organizations.amazonaws.com`), is one of the most destructive and disruptive actions available in AWS. It immediately triggers a 90-day grace period where the account is suspended, rendering all resources and data inaccessible before permanent termination. Attackers can leverage this action to destroy evidence, severely disrupt business operations, or eliminate critical compute and data resources, classifying any unauthorized occurrence as a critical security incident.

## Attack Chain

1. An adversary obtains root credentials for a target AWS account or gains management-level administrative access to an AWS Organizations management account.
2. The adversary executes the `CloseAccount` API call, either directly against the compromised account or against a member account within the organization.
3. The targeted AWS account immediately enters a 90-day suspension period as a result of the API call.
4. All access to resources, applications, and data within the suspended account is revoked, preventing legitimate users from operating.
5. During the suspension, the adversary may achieve objectives such as destroying evidence of compromise or creating maximum business disruption.
6. If no intervention occurs, the AWS account is permanently terminated after the 90-day grace period, leading to irreversible loss of all data and infrastructure.

## Impact

An unauthorized AWS account closure is a critical incident leading to immediate and severe consequences. Upon closure, all resources and data within the account become inaccessible for a 90-day suspension period, effectively crippling business operations that rely on the affected AWS environment. This can result in significant data loss, prolonged service outages, reputational damage, and financial costs associated with recovery or rebuilding infrastructure. The impact is pervasive, affecting all sectors and potentially leading to permanent data destruction if the account is not restored within the grace period.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM to detect `CloseAccount` API calls made via AWS CloudTrail logs.
* Monitor `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` fields in CloudTrail logs to identify the actor initiating account closure.
* Contact AWS Support immediately if an unauthorized account closure is detected to attempt cancellation/restoration within the 90-day grace period.
* Restrict `organizations:CloseAccount` and `account:CloseAccount` permissions to a minimal set of trusted administrative identities to reduce attack surface.
* Implement robust change management processes to ensure all legitimate AWS account closures have corresponding records and approvals, serving as a filter for the `falsepositives` of the Sigma rule.
