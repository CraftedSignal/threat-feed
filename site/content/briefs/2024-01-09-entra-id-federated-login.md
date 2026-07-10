---
title: Entra ID Service Principal Federated Credential Authentication by Unusual Client
slug: 2024-01-09-entra-id-federated-login
description: Detection of initial Entra ID service principal authentication using a federated identity credential, potentially indicating a rogue identity provider abusing compromised applications.
date: "2024-01-09T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - entra-id
  - federated-credentials
  - byoidp
  - initial-access
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
  - https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
  - https://github.com/dirkjanm/ROADtools
rules:
  - title: Entra ID Service Principal Federated Credential Authentication by Unusual Client
    description: Detects first-time authentication of a service principal using federated credentials, potentially indicating BYOIDP abuse.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098.001
      - T1550.001
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Unusual Client Federated Credential
    description: Detects federated credential usage from unusual client IPs
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098.001
      - T1550.001
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies when a service principal authenticates using a federated identity credential for the first time within a defined historical window. This event indicates that Entra ID has validated a JWT token, potentially against an external OIDC identity provider, and subsequently issued an access token. While this process is standard for CI/CD workflows like GitHub Actions and Azure DevOps, adversaries may exploit it by configuring rogue identity providers (BYOIDP) to authenticate as compromised applications. Detecting the first-time usage of a federated credential for a service principal is critical for identifying potential BYOIDP attacks. The rule examines Azure Sign-In Logs for service principals using federated identity credentials, excluding known good tenant IDs, to surface potentially malicious activity.

## Attack Chain

1.  The adversary compromises an application or service principal within the target Entra ID environment.
2.  The attacker configures a rogue identity provider (BYOIDP) that they control.
3.  The adversary creates a federated identity credential on the compromised application, linking it to their rogue identity provider.
4.  The compromised application requests authentication, triggering Entra ID to validate a JWT token against the attacker's rogue identity provider.
5.  Entra ID issues an access token to the compromised application based on the validation from the rogue identity provider.
6.  The adversary uses the access token to access resources and data within the Entra ID environment, masquerading as the legitimate application.
7.  The adversary escalates privileges or moves laterally within the environment using the compromised application's permissions.

## Impact

A successful BYOIDP attack can grant an adversary unauthorized access to sensitive data and resources within an Entra ID environment. This can lead to data breaches, service disruptions, and significant reputational damage. The impact depends on the permissions and access rights of the compromised service principal. Undetected, this attack can persist, allowing continued unauthorized access.

## Recommendation

*   Enable collection of Microsoft Entra ID Sign-In Logs and stream them into your SIEM (per the rule's setup instructions) to gain visibility into federated credential usage.
*   Deploy the provided Sigma rule `Entra ID Service Principal Federated Credential Authentication by Unusual Client` to detect initial federated credential usage by service principals. Tune the rule based on your environment and known CI/CD deployments.
*   When the rule triggers, investigate the federated credential configuration in Entra ID, focusing on the issuer URL, creation time, and the user who added the credential as described in the rule's `note` section.
*   Review audit logs for recent changes to application federated credentials, correlating with sign-in logs to identify unauthorized modifications.
*   Baseline applications expected to use federated credentials and maintain a list of approved identity providers, as suggested in the rule's `false_positives` section.
*   Prioritize investigation of alerts where the `azure.signinlogs.caller_ip_address` originates from an unexpected location or infrastructure, as described in the rule's `note` section.
