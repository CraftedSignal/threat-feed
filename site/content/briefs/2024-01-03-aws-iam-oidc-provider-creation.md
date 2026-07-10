---
title: AWS IAM OIDC Provider Created by Rare User
slug: 2024-01-03-aws-iam-oidc-provider-creation
description: An uncommon user or role creating an OpenID Connect (OIDC) Identity Provider in AWS IAM can indicate an attacker establishing persistent, federated access by creating rogue OIDC providers to assume roles using attacker-controlled IdP tokens.
date: "2024-01-03T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - oidc
  - persistence
  - cloud
vendors:
  - Amazon Web Services
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
rules:
  - title: AWS IAM OIDC Provider Created
    description: Detects the creation of an OpenID Connect (OIDC) Identity Provider in AWS IAM.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1484.002
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM OIDC Provider Trust Policy Update
    description: Detects updates to IAM role trust policies to include the newly created OIDC provider.
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
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when a previously unseen user or role creates an OpenID Connect (OIDC) Identity Provider within an AWS IAM environment. OIDC providers facilitate web identity federation, enabling external identity providers to authenticate users for assuming IAM roles. Threat actors, especially those with existing administrative access, may abuse this by creating unauthorized OIDC providers. This allows them to maintain persistent access, potentially bypassing credential rotations, by assuming roles using tokens from an IdP they control. While legitimate OIDC provider creation can occur, especially within CI/CD pipelines or Kubernetes environments, any unfamiliar user initiating this activity warrants immediate investigation. This rule focuses on the initial creation event as a key indicator of potential compromise.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the AWS environment, potentially through compromised credentials, or exploiting an existing vulnerability.
2.  **Privilege Escalation:** The attacker escalates privileges within the AWS environment to obtain the necessary permissions to create IAM resources, specifically OIDC providers. This might involve exploiting misconfigured IAM roles or policies.
3.  **Discovery:** The attacker uses AWS APIs (e.g., `iam:ListRoles`, `iam:GetRole`) to identify potential target roles to which they want to establish persistent access.
4.  **Credential Access:** The attacker crafts a malicious OIDC provider configuration. This involves setting up a rogue identity provider controlled by the attacker.
5.  **Persistence:** The attacker creates a new IAM OIDC provider using the `CreateOpenIDConnectProvider` API call, configuring it to trust the attacker-controlled identity provider.
6.  **Trust Modification:** The attacker modifies the trust policy of existing IAM roles using `UpdateAssumeRolePolicy` to allow principals authenticated via the rogue OIDC provider to assume those roles.
7.  **Defense Evasion:** The attacker may attempt to obfuscate their activity by using unusual naming conventions or by creating the OIDC provider during off-peak hours.
8.  **Impact:** The attacker leverages their newly established federated access to assume roles and access sensitive AWS resources, potentially leading to data exfiltration, service disruption, or other malicious activities. They use `AssumeRoleWithWebIdentity` to obtain temporary credentials.

## Impact

Successful exploitation allows attackers to establish persistent access within the AWS environment, even after credential rotations. The impact can range from unauthorized access to sensitive data and resources, to complete compromise of the AWS environment. Creating rogue OIDC providers can enable attackers to bypass multi-factor authentication controls. The number of potential victims depends on the scope of the compromised AWS environment, potentially affecting organizations of any size that rely on AWS services.

## Recommendation

*   Deploy the Sigma rule "AWS IAM OIDC Provider Created by Rare User" to detect anomalous OIDC provider creation events (rule "AWS IAM OIDC Provider Created by Rare User"). Enable AWS CloudTrail logs for monitoring IAM events (log source: aws.cloudtrail).
*   Restrict `iam:CreateOpenIDConnectProvider` permissions to authorized roles or users only.
*   Review and remove any IAM roles that trust the rogue provider if unauthorized OIDC provider is identified based on alert.
*   Monitor AWS CloudTrail logs for `AssumeRoleWithWebIdentity` calls associated with newly created OIDC providers to detect potential abuse (log source: aws.cloudtrail).
*   Implement AWS Config rules to monitor identity provider configurations and detect unauthorized changes.
