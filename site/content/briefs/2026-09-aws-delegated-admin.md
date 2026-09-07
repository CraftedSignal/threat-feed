---
title: AWS Organizations Delegated Administrator Registration
slug: 2026-09-aws-delegated-admin
description: An attacker with compromised credentials possessing 'organizations:RegisterDelegatedAdministrator' permissions can escalate privileges by designating an attacker-controlled member account as a delegated administrator for sensitive services to gain organization-wide control.
date: "2026-09-07T10:42:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - organizations
  - persistence
  - privilege-escalation
vendors:
  - Amazon
products:
  - AWS Organizations
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries who compromise a principal in the management account with overly permissive Organizations policies can register an attacker-controlled member account as a delegated administrator, then use that foothold to escalate privileges across all accounts in the organization.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
    evidence: Adversaries who compromise a principal in the management account with overly permissive Organizations policies can register an attacker-controlled member account as a delegated administrator.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/organizations/latest/APIReference/API_RegisterDelegatedAdministrator.html
  - https://cymulate.com/blog/aws-delegated-admin-org-takeover/
rules:
  - title: Detect AWS Organizations Delegated Administrator Registration
    description: Detects usage of the RegisterDelegatedAdministrator API, which can be used for persistence or privilege escalation in AWS environments.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection rule for RegisterDelegatedAdministrator to the SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Rule definition in brief.
    - action: Perform an audit of current delegated administrators using ListDelegatedAdministrators.
      owner: SOC
      due: 48h
      evidence: Triage and analysis guide in brief.
  hunt_leads:
    - lead: Review all past RegisterDelegatedAdministrator API events for any non-approved delegations.
      technique_id: T1098.003
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Triage and analysis guide.
---

AWS Organizations allows the management account to designate member accounts as delegated administrators for specific AWS services. This allows the delegated account to manage the service on behalf of the organization without requiring direct access to the management account. Threat actors who compromise a principal with excessive 'organizations:RegisterDelegatedAdministrator' permissions can exploit this mechanism to elevate an attacker-controlled member account to a position of organization-wide administrative authority. This provides an effective method for persistence and lateral movement, as the attacker can subsequently use the delegated administrator's permissions to manipulate sensitive resources, modify IAM policies, or compromise other member accounts across the entire organization. Defenders must monitor CloudTrail logs for unexpected usage of the RegisterDelegatedAdministrator API to prevent unauthorized privilege escalation.

## Attack Chain

1. Attacker compromises an IAM principal in the AWS management account that possesses overly permissive IAM policies (e.g., broad organizations:* access).
2. Attacker enumerates available AWS accounts within the organization to identify a candidate member account for takeover.
3. Attacker uses the compromised credentials to invoke the 'organizations:RegisterDelegatedAdministrator' API call.
4. Attacker specifies the target member account ID and the desired AWS service (e.g., Identity Center or CloudFormation StackSets) in the API request parameters.
5. AWS registers the attacker-controlled account as the delegated administrator for the target service, granting it organization-wide administrative scope.
6. Attacker authenticates as the delegated administrator identity.
7. Attacker executes administrative actions (e.g., creating new IAM roles, modifying StackSets, or accessing sensitive data) across the organization.
8. Attacker establishes persistence and exfiltrates data or pivots further into the organization's infrastructure.

## Impact

Successful exploitation results in full administrative control over specific AWS services for the entire organization. This leads to privilege escalation, potential lateral movement to all member accounts, and the ability to modify organizational security policies, create backdoors, or exfiltrate sensitive data managed within the organization's cloud environment.

## Recommendation

* Deploy detection for 'organizations:RegisterDelegatedAdministrator' in AWS CloudTrail to identify unauthorized delegation attempts.
* Audit all currently registered delegated administrators using 'organizations:ListDelegatedAdministrators' to ensure they align with the organization's planned configuration.
* Apply the principle of least privilege to IAM policies, ensuring 'organizations:RegisterDelegatedAdministrator' is restricted to a dedicated, MFA-authenticated role.
* Review and revoke broad 'organizations:*' permissions from non-essential management account principals.
* Investigate any successful API calls identified in the detection rule to verify if the delegated account belongs to the organization's legitimate inventory.
