---
title: Entra ID Service Principal Federated Issuer Modification
slug: 2024-01-22-entra-id-federated-issuer-modified
description: Entra ID (Azure AD) service principal federated issuers can be modified by an attacker to establish persistence within a target environment.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - persistence
  - federated_identity
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_service_principal_federated_issuer_modified.toml
rules:
  - title: Detect Federated Identity Provider Modification in Azure AD
    description: Detects modifications to federated identity providers in Azure AD, which can indicate malicious attempts to establish persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1550.001
    data_sources:
      - cloudtrail
      - azure
  - title: Detect Federated Identity Provider Creation in Azure AD
    description: Detects creation of federated identity providers in Azure AD, which can indicate malicious attempts to establish persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1550.001
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

Attackers can modify Entra ID (Azure AD) service principal federated issuers to establish persistence. This involves manipulating the trust relationships between the service principal and external identity providers. Successful modification allows unauthorized access to resources within the Azure environment. Although the referenced material does not specify attacker details, successful exploitation can lead to significant data breaches and unauthorized control over cloud resources. Defenders must monitor for unauthorized modifications to federated issuer configurations to mitigate this threat.

## Attack Chain

1. The attacker gains initial access to an Azure AD tenant with sufficient privileges to manage service principals and federated identity providers. This could be through compromised credentials or exploitation of a privileged account.
2. The attacker identifies a target service principal within the Azure AD tenant.
3. The attacker discovers the existing federated identity providers associated with the target service principal.
4. The attacker modifies the configuration of an existing federated identity provider or adds a new one controlled by the attacker. This involves altering the metadata URL or issuer URI.
5. The attacker configures their own identity provider to issue tokens that are trusted by the modified federated identity provider in Azure AD.
6. Using the attacker-controlled identity provider, the attacker obtains a token for the target service principal.
7. The attacker uses the obtained token to authenticate to Azure resources that the service principal has access to.
8. The attacker maintains persistent access to the Azure environment through the modified federated identity provider, even if the original access method is revoked.

## Impact

Successful modification of a federated issuer allows attackers to maintain persistent access to Azure resources, potentially leading to data exfiltration, unauthorized access to sensitive information, and disruption of cloud services. The impact depends on the permissions assigned to the compromised service principal.
