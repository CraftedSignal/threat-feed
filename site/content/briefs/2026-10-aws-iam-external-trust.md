---
title: Detection of AWS IAM Roles Created with External Trust Policies
slug: 2026-10-aws-iam-external-trust
description: Detection of AWS IAM role creation events with trust policies configured to permit 'sts:AssumeRole' from external AWS accounts or wildcard principals, a common technique for establishing persistent backdoors.
date: "2026-10-19T02:51:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - cloud
  - aws
vendors:
  - Amazon
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This configuration may provide persistent access if the principal can assume the role.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This technique is often used to establish persistent access or facilitate cross-account privilege escalation.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html
  - https://stratus-red-team.cloud/attack-techniques/aws/aws.persistence.iam-backdoor-role/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review all IAM CreateRole events in CloudTrail for the last 30 days identifying external or wildcard trusts.
      owner: SOC
      due: 48h
      evidence: Source documentation on monitoring CreateRole events.
  mitigation_plan:
    - priority: short_term
      action: Enforce SCPs limiting role trust relationship creation to authorized AWS accounts only.
      owner: Cloud Security
      addresses: T1098.003
      evidence: Industry standard practice for preventing cross-account privilege escalation.
---

This brief addresses the risk of unauthorized or suspicious AWS IAM role creation where the resulting trust policy permits cross-account access or wildcard principal access. Attackers leverage the 'sts:AssumeRole' permission to create backdoors, allowing them to maintain persistent access or move laterally between AWS environments. By creating a role that trusts an external account under their control, or by utilizing broad wildcard principals, an attacker can bypass traditional IAM controls after gaining initial access to an AWS environment. Defenders should monitor 'CreateRole' CloudTrail events to identify roles configured with permissive trust policies that deviate from established organizational security baselines.

## Attack Chain

1. Attacker gains initial access to an AWS environment with sufficient IAM creation permissions.
2. Attacker executes the 'iam:CreateRole' API action.
3. Attacker provides a crafted 'AssumeRolePolicyDocument' within the request.
4. The policy document specifies a trust relationship allowing 'sts:AssumeRole' for an external AWS account ID or a broad wildcard principal.
5. AWS IAM service processes the request and creates the role with the defined trust policy.
6. Attacker confirms the role creation via 'GetRole' or 'ListRoles' to retrieve the Role ARN.
7. Attacker assumes the newly created role from the external account or permitted identity to perform malicious actions.

## Impact

Successful exploitation allows attackers to establish persistent, cross-account access into target environments. This can lead to unauthorized data exfiltration, privilege escalation, and lateral movement across multiple AWS accounts. While the creation event itself does not confirm unauthorized access, it serves as a critical indicator for potential persistence mechanisms being staged by an attacker.

## Recommendation

* Monitor AWS CloudTrail for 'CreateRole' events where the 'assumeRolePolicyDocument' contains cross-account or wildcard principals.
* Audit existing IAM roles periodically to identify and remove permissive trust relationships.
* Implement service control policies (SCPs) to restrict the ability to create roles that trust external AWS accounts or wildcard principals without explicit authorization.
* Tune security detection systems to ignore known, approved cross-account integrations while alerting on deviations.
