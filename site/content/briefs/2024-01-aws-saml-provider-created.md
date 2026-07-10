---
title: AWS IAM SAML Provider Creation for Persistence
slug: 2024-01-aws-saml-provider-created
description: Detects the creation of a new SAML Identity Provider (IdP) in AWS IAM, potentially indicating an adversary establishing persistent, federated access to AWS accounts by forging SAML assertions from an IdP they control.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - saml
  - persistence
  - cloud
vendors:
  - AWS
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateSAMLProvider.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
rules:
  - title: AWS IAM SAML Provider Created
    description: Detects the creation of a new SAML Identity Provider (IdP) in AWS IAM.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM AssumeRoleWithSAML Activity
    description: Detects AssumeRoleWithSAML API calls, which may indicate use of a newly created or compromised SAML Provider
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1550.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Role Trust Policy Modification Referencing SAML Provider
    description: Detects updates to IAM role trust policies that reference a SAML provider, potentially indicating malicious trust relationship establishment
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1484.002
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

This detection identifies the creation of a new SAML Identity Provider (IdP) within Amazon Web Services Identity and Access Management (AWS IAM).  SAML providers facilitate federated authentication between AWS and external identity providers. An attacker with administrative access could create a rogue SAML provider to maintain persistent access to AWS environments, bypassing normal credential rotation. This is achieved by forging SAML assertions, enabling the attacker to assume roles and access resources. The creation of SAML providers is typically a rare event, tied to initial SSO setup or significant infrastructure changes.  This rule aims to detect anomalous instances of this event that deviate from established change management processes. Defenders should prioritize monitoring and validating these actions.

## Attack Chain

1.  An adversary gains initial administrative access to an AWS account. This could be through compromised credentials or exploiting a misconfiguration.
2.  The attacker attempts to elevate privileges within the AWS environment to gain the necessary permissions to create IAM resources.
3.  The adversary creates a new, malicious SAML Identity Provider (IdP) within AWS IAM using the `CreateSAMLProvider` API call.
4.  The attacker uploads a crafted SAML metadata document to the newly created SAML provider, defining the trust relationship.
5.  The attacker creates or modifies IAM roles to trust the malicious SAML provider. This allows users authenticated via the attacker's IdP to assume these roles.
6.  The attacker forges SAML assertions using the attacker-controlled IdP, authenticating as a user who is authorized to assume a trusted role.
7.  The attacker uses the `AssumeRoleWithSAML` API call to assume the IAM role, gaining access to AWS resources.
8.  The attacker maintains persistent access to the AWS environment, even if the original compromised credentials are rotated.

## Impact

Successful exploitation allows attackers to establish persistent access within an AWS environment.  The potential damage includes unauthorized access to sensitive data, resource manipulation, and service disruption.  The number of affected victims is dependent on the scope of the initial compromise and the permissions granted to the roles assumed via the rogue SAML provider. Organizations utilizing federated authentication are particularly vulnerable.

## Recommendation

*   Deploy the Sigma rule `AWS IAM SAML Provider Created` to your SIEM and tune for your environment to detect the creation of new SAML providers (rule).
*   Restrict `iam:CreateSAMLProvider` permissions to a limited set of administrative roles to reduce the attack surface (content).
*   Monitor AWS CloudTrail logs for `CreateSAMLProvider` events, focusing on unexpected user identities or source IP addresses (rule).
*   Review existing IAM roles and trust policies for unauthorized trust relationships with external SAML providers (content).
*   Implement AWS Config rules to continuously monitor identity provider configurations for deviations from approved baselines (content).
