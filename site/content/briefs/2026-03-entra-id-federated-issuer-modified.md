---
title: Entra ID Federated Identity Credential Issuer Modified
slug: 2026-03-entra-id-federated-issuer-modified
description: Modification of the issuer URL of a federated identity credential in Entra ID can allow an attacker to authenticate as the application's service principal, granting persistent access to Azure resources by pointing to an attacker-controlled identity provider and bypassing normal authentication.
date: "2026-03-18T21:22:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra_id
  - federated_identity
  - persistence
  - privilege_escalation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
references:
  - https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
  - https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
rules:
  - title: Entra ID Federated Identity Credential Issuer Modified (Sysmon)
    description: Detects changes to the issuer URL of a federated identity credential based on process execution that makes the change.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
      - T1484.002
    data_sources:
      - process_creation
      - windows
  - title: Entra ID Federated Identity Credential Issuer Modified (Audit Logs)
    description: Detects modifications to the issuer URL of a federated identity credential in Entra ID using audit logs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
      - T1484.002
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection identifies modifications to the issuer URL within a federated identity credential on an Entra ID application. Federated identity credentials enable applications to authenticate using tokens from external identity providers (e.g., GitHub Actions, AWS) without managing secrets. An attacker can exploit this by changing the issuer to an attacker-controlled identity provider, enabling them to generate valid tokens and authenticate as the application's service principal. This technique provides persistent access to Azure resources with the application's permissions, effectively bypassing traditional secret-based authentication. The detection logic focuses on the "Update application" event within Entra ID audit logs, specifically targeting changes to the "FederatedIdentityCredentials" property. It is applicable to environments using Azure and Entra ID and is relevant for defenders aiming to prevent unauthorized access and maintain the integrity of their cloud infrastructure.

## Attack Chain

1. An attacker compromises an Entra ID account with sufficient privileges to modify application registrations.
2. The attacker navigates to the Entra ID portal or uses PowerShell/Azure CLI to locate a target application with federated identity credentials configured.
3. The attacker modifies the "Issuer" URL of an existing Federated Identity Credential within the application registration. They replace the legitimate issuer URL with a URL controlled by the attacker.
4. The attacker configures their own identity provider to issue tokens that match the application's expected audience and subject claims.
5. The attacker crafts a malicious token from their identity provider, impersonating the legitimate service principal.
6. The attacker uses the crafted token to authenticate to Azure resources, bypassing normal authentication controls.
7. The attacker leverages the application's permissions to access sensitive data, modify configurations, or deploy malicious code.
8. The attacker maintains persistent access to the Azure environment by continuing to use the compromised federated identity configuration.

## Impact

Successful exploitation allows an attacker to gain persistent access to Azure resources with the permissions of the compromised application. This could lead to data breaches, unauthorized modifications to critical infrastructure, and deployment of malicious code within the cloud environment. The impact is significant because it bypasses traditional authentication methods and relies on a trust relationship established with an external identity provider. The rule is rated high severity because it directly addresses a persistence and privilege escalation technique that can severely impact the confidentiality, integrity, and availability of cloud resources.

## Recommendation

*   Enable the Azure integration with Microsoft Entra ID Audit Logs data stream to ingest data in your Elastic Stack deployment, as required by the rule setup instructions.
*   Deploy the provided Sigma rule to your SIEM to detect unauthorized modifications to federated identity credential issuers in Entra ID (`Entra ID Federated Identity Credential Issuer Modified`).
*   Review `azure.auditlogs.properties.initiated_by.user.userPrincipalName` and `ipAddress` logs to determine the source of detected changes, as recommended in the rule's triage notes.
*   Implement conditional access policies and PIM (Privileged Identity Management) to protect application management operations within Entra ID, as suggested in the rule's response and remediation guidance.
