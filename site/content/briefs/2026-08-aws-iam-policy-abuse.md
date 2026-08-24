---
title: AWS IAM Privilege Escalation via Policy Version Manipulation
slug: 2026-08-aws-iam-policy-abuse
description: Attackers with IAM policy management permissions can escalate privileges by creating permissive policy versions or switching the default version of an existing customer-managed policy.
date: "2026-08-24T09:51:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - aws
  - privilege-escalation
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Attackers with iam:CreatePolicyVersion or iam:SetDefaultPolicyVersion on a privileged policy can introduce a permissive policy document and activate it.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Abuse of CreatePolicyVersion or SetDefaultPolicyVersion allows attackers to elevate effective permissions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.005
    technique_name: ""
    evidence: Attackers use these APIs to escalate effective permissions without attaching a new policy.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
rules:
  - title: Detect AWS IAM Policy Version Manipulation
    description: Detects unauthorized CreatePolicyVersion or SetDefaultPolicyVersion calls, which may indicate privilege escalation via policy modification.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
      - T1548.005
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Review current IAM policy update logs for non-automated activity
      owner: SOC
      due: 48h
      evidence: Source documentation identifies these APIs as high-impact privilege escalation vectors
  mitigation_plan:
    - priority: short_term
      action: Restrict IAM policy management permissions to strictly controlled service accounts
      owner: IT Operations
      addresses: T1548.005
---

This threat involves the abuse of AWS Identity and Access Management (IAM) API calls to escalate privileges without attaching new policies, which is a common indicator of unauthorized activity. By leveraging `CreatePolicyVersion` or `SetDefaultPolicyVersion` permissions on an existing customer-managed policy, an attacker can modify the permissions associated with a principal. This technique is effective because the changes are applied to existing policies already attached to roles or users, allowing attackers to broaden the scope of permissions silently. This method is particularly dangerous when the targeted policy is attached to administrative or break-glass roles. Organizations should monitor these API actions, particularly when performed by users or roles that are not designated automation service accounts.

## Impact

Successful exploitation allows an attacker to elevate their effective permissions or those of a compromised role, potentially leading to full account takeover or unauthorized access to sensitive cloud resources. Because the policy modification occurs within an existing, legitimate policy object, the activity may bypass basic security alerts that look primarily for the attachment of new or unrecognized policies.

## Recommendation

- Enable logging for `CreatePolicyVersion` and `SetDefaultPolicyVersion` events in AWS CloudTrail.
- Implement monitoring to identify users and roles performing these actions outside of known CI/CD or automation pipelines.
- Audit high-privilege IAM policies to identify which principals have the authority to update their own versioning.
- Deploy the detection logic provided below to identify non-standard usage of these policy management APIs.
