---
brief_id: brief-2026-11-20-aws-iam-password-policy-recon
event_id: brief-2026-11-20-aws-iam-password-policy-recon
revision: 1
activity_at: "2026-11-20T14:00:49Z"
title: AWS IAM Password Policy Recon by Rare User
slug: 2026-11-aws-iam-password-policy-recon
description: This rule uses a New Terms approach to identify rare combinations of cloud.account.id, user.name, and source.as.organization.name performing AWS GetAccountPasswordPolicy API calls, which may indicate reconnaissance activity by adversaries planning credential attacks.
date: "2026-11-20T14:00:49Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - 'Domain: Cloud'
  - 'Data Source: AWS'
  - 'Data Source: Amazon Web Services'
  - 'Domain: Identity'
  - 'Platform: AWS'
  - 'Data Source: AWS CloudTrail'
  - 'Service: AWS IAM'
  - 'Tactic: Discovery'
  - 'Rule Type: New Terms'
  - 'Resources: Investigation Guide'
products:
  - AWS IAM
affected_os:
  - AWS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1201
    technique_name: Password Policy Discovery
    evidence: Adversaries with compromised credentials enumerate the password policy to understand credential requirements and plan password spraying, brute force, or new-access-key persistence.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_iam_password_policy_recon_by_rare_user.toml
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html
  - https://www.atomicredteam.io/docs/atomics/T1201
rules:
  - title: AWS IAM Password Policy Recon by Rare User
    description: Identifies the first time, within a lookback window, an identity retrieves the AWS account password policy via the IAM GetAccountPasswordPolicy API using New Terms to detect rare combinations of cloud.account.id, user.name, and source.as.organization.name.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1201
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
---

## Overview
This rule identifies the first time, within a lookback window, that an identity retrieves the AWS account password policy via the IAM GetAccountPasswordPolicy API. Adversaries with compromised credentials may enumerate the password policy to understand credential requirements and plan password spraying, brute force, or new-access-key persistence. The rule uses a New Terms mechanism to detect when a unique combination of cloud.account.id, user.name, and source.as.organization.name appears.

## Attack Chain
Adversaries with compromised credentials call the GetAccountPasswordPolicy API to discover security posture details, which can inform downstream activities such as password spraying or brute force attacks.

## Impact
Successful unauthorized enumeration of IAM password policies assists attackers in identifying account security requirements, facilitating credential stuffing or password spraying campaigns.

## Recommendation
- Confirm who user.name and aws.cloudtrail.user_identity.arn represent and whether policy reads are expected for that principal.
- Review source.ip, source.as.organization.name, and geolocation to see if the call aligns with normal network activity.
- Inspect user_agent.original for unfamiliar offensive tooling.
- Correlate with STS activity (GetCallerIdentity, AssumeRole) or IAM modifications (CreateAccessKey, CreateLoginProfile).
- Rotate credentials for the implicated principal if activity is unexpected.
