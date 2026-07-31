---
title: Detection of Unusual AWS IAM Guardrail Policy Deletion
slug: 2026-07-aws-iam-policy-deletion
description: This threat brief identifies a detection strategy for attackers attempting defense evasion or persistence by deleting sensitive AWS IAM managed policies using previously unseen identities.
date: "2026-07-31T09:23:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - persistence
  - aws
  - iam
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries who have obtained elevated IAM privileges may delete policies to remove restrictive permissions boundaries, eliminate deny-based guardrails, or clean up after a privilege escalation operation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: 'Policy deletion is a privilege-escalation or defense-evasion primitive: removing a deny-based policy or permissions boundary silently expands the effective access of every principal that policy applied to.'
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_iam_managed_policy_deleted_unusual_identity.toml
rules:
  - title: Detect Unusual Deletion of AWS IAM Guardrail Policies
    description: Detects the first time an AWS identity successfully deletes an IAM managed policy containing guardrail-related keywords, potentially indicating defense evasion or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1098
      - T1562
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Adversaries with elevated privileges often seek to impair security controls or establish persistent access by modifying identity structures. In AWS environments, this frequently involves deleting IAM managed policies that act as permissions boundaries or guardrails (e.g., policies containing "Boundary", "Deny", "Restrict", or "Guardrail"). By removing these restrictive policies, attackers can silently expand their effective permissions across the account.

This activity is often performed after initial access and privilege escalation. Defenders should be alerted when an identity performs this deletion for the first time in a 7-day period, as this behavioral anomaly may signify the use of compromised credentials or unauthorized administrative actions. Infrastructure-as-code (IaC) tools such as Terraform, CloudFormation, Pulumi, and Ansible are excluded from this detection logic to differentiate routine automated configuration changes from potentially malicious activity.

## Impact

Successful exploitation of this technique leads to the degradation of the account's security posture. By deleting permission boundaries or deny-based policies, an attacker can bypass intended access constraints, potentially escalating privileges, accessing sensitive data, or establishing long-term persistence within the environment. If unchecked, this can facilitate large-scale unauthorized data access or complete account takeover.

## Recommendation

Prioritize the following actions to detect and mitigate unauthorized IAM modifications:

- Deploy the provided Sigma rule to your SIEM to monitor for 'DeletePolicy' events originating from unexpected identities.
- Investigate any 'DeletePolicy' event involving a policy ARN containing guardrail-related keywords (Boundary, Deny, Restrict, Guard, SCP, Guardrail).
- Cross-reference the identified principal's activity with other privilege escalation indicators such as 'CreatePolicyVersion', 'AttachRolePolicy', or 'UpdateAssumeRolePolicy'.
- Verify that the IAM identity responsible for the policy deletion is an authorized management role and not an unexpected or recently assumed principal.
