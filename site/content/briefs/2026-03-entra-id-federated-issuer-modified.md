---
title: Entra ID Federated Identity Credential Issuer Modified
slug: 2026-03-entra-id-federated-issuer-modified
description: Modification of the issuer URL of a federated identity credential in Entra ID can allow an attacker to authenticate as the application's service principal, granting persistent access to Azure resources by pointing to an attacker-controlled identity provider and bypassing normal authentication.
date: "2026-03-18T21:22:55Z"
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

This detection identifies modifications to the issuer URL within a federated identity credential on an Entra ID application. Federated identity credentials enable applications to authenticate using tokens from external identity providers (e.g., GitHub Actions, AWS) without managing secrets. An attacker can exploit this by changing the issuer to an attacker-controlled identity provider, enabling them to generate valid tokens and authenticate as the application's service principal. This technique…
