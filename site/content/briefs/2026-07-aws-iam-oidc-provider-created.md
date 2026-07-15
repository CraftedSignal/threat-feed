---
title: AWS IAM OpenID Connect Provider Creation by Rare User
slug: 2026-07-aws-iam-oidc-provider-created
description: Adversaries with administrative access to an AWS account may create rogue OpenID Connect (OIDC) Identity Providers to establish persistent, federated access that bypasses credential rotation and allows them to assume IAM roles using tokens from an attacker-controlled Identity Provider.
date: "2026-07-15T14:17:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - persistence
  - privilege-escalation
  - defense-evasion
  - aws
  - iam
vendors:
  - Amazon
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries who have gained administrative access may create rogue OIDC providers to establish persistent, federated access that survives credential rotation.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
    evidence: Adversaries... may create rogue OIDC providers to establish persistent, federated access... This technique allows attackers to assume roles using tokens from an IdP they control.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
    evidence: Adversaries... may create rogue OIDC providers to establish persistent, federated access that survives credential rotation.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_oidc_provider_created.toml
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
rules:
  - title: AWS IAM OpenID Connect Provider Creation
    description: Detects the creation of an OpenID Connect (OIDC) Identity Provider in AWS IAM. While legitimate for web identity federation, adversaries may create rogue OIDC providers for persistent access after compromising administrative credentials. This rule provides the basis for detection; further tuning in your SIEM can incorporate 'rare user' logic.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1484.002
    data_sources:
      - aws
      - cloudtrail
rules_count: 1
---

This threat brief details the creation of OpenID Connect (OIDC) Identity Providers within AWS Identity and Access Management (IAM) by uncommon users or roles, a technique frequently abused by adversaries. OIDC providers are legitimately used to enable web identity federation, allowing users authenticated by external identity providers (like Google, GitHub, or custom OIDC-compliant services) to assume IAM roles and access AWS resources. However, if an attacker gains administrative access to an AWS environment, they can create a malicious OIDC provider to establish a highly persistent backdoor. This allows them to maintain federated access, often surviving credential rotation, by generating tokens from an Identity Provider (IdP) they control to assume trusted IAM roles. This activity, especially when performed by a user or role that has not previously created such providers, is a strong indicator of compromise or unauthorized access and requires immediate investigation.

## Impact

Successful exploitation allows adversaries to establish a persistent and stealthy access mechanism to the compromised AWS environment. By controlling their own OIDC IdP, attackers can assume any IAM role configured to trust their rogue provider, gaining extensive access to AWS services, data, and resources. This could lead to unauthorized data exfiltration, modification or deletion of critical infrastructure, disruption of services, and further privilege escalation within the cloud environment. The nature of federated access makes detection and remediation challenging, as traditional credential rotations may not revoke the attacker's access. The persistence established can be difficult to eradicate, enabling long-term compromise and control over the victim's AWS infrastructure.

## Recommendation

* Deploy the provided Sigma rule to detect `CreateOpenIDConnectProvider` actions within your AWS environment, ensuring it's integrated with your SIEM and tuned for your specific baseline.
* Implement least privilege principles by restricting `iam:CreateOpenIDConnectProvider` permissions to only authorized roles and users that explicitly require this capability.
* Enable AWS Config rules to continuously monitor and report on changes to identity provider configurations, including the creation of new OIDC providers.
* For suspicious detections, review AWS CloudTrail logs, specifically `aws.cloudtrail.user_identity.arn` to identify the actor and `aws.cloudtrail.request_parameters` to examine the OIDC provider's URL and client IDs.
* Validate any OIDC provider creation against approved change management processes, especially for new or uncommon actors.
