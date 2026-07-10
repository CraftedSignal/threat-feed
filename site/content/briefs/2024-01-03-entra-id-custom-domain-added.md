---
title: Entra ID Custom Domain Added or Verified
slug: 2024-01-03-entra-id-custom-domain-added
description: Detection of custom domain additions or verifications in Entra ID, a precursor to potentially malicious domain federation for Golden SAML attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - entra-id
  - domain-federation
  - golden-saml
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1584
    technique_name: Compromise Infrastructure
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29
  - https://learn.microsoft.com/en-us/graph/api/domain-post-domains
  - https://learn.microsoft.com/en-us/graph/api/domain-verify
  - https://medium.com/tenable-techblog/roles-allowing-to-abuse-entra-id-federation-for-persistence-and-privilege-escalation-df9ca6e58360
  - https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/
rules:
  - title: Entra ID Custom Domain Added or Verified
    description: Detects when a custom domain is added or verified in an Entra ID tenant, a precursor to malicious domain federation.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1584.001
    data_sources:
      - auditlogs
      - azure
  - title: Entra ID Domain Authentication Settings Modified
    description: Detects modifications to domain authentication settings in Entra ID, which could indicate domain federation configuration.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1584.001
    data_sources:
      - auditlogs
      - azure
rules_count: 2
---

This alert detects the addition or verification of custom domains within an Entra ID tenant. While legitimate in some administrative contexts, these actions are infrequent and can signal the initial stages of a Golden SAML or BYOIDP (Bring Your Own Identity Provider) attack. Attackers might add a domain to configure domain federation, routing authentication through an attacker-controlled identity provider. Defenders should investigate such events when they lack corresponding change requests or IT workflows. The rule is based on Microsoft Entra ID Audit Logs.

## Attack Chain

1.  Attacker gains unauthorized access to an Entra ID tenant, typically requiring Global Administrator or Domain Administrator privileges, possibly through compromised credentials or privilege escalation.
2.  Attacker adds a new, unverified custom domain to the Entra ID tenant using the Azure portal, Microsoft Graph API, or PowerShell. The added domain is typically attacker-controlled.
3.  The "Add unverified domain" event is logged in the Azure audit logs.
4.  Attacker verifies the custom domain by adding a specific TXT record to the domain's DNS settings as instructed by Entra ID.
5.  The "Verify domain" event is logged in the Azure audit logs.
6.  Attacker configures domain federation settings to point to an attacker-controlled identity provider (IdP).
7.  Users authenticating to cloud applications are redirected to the malicious IdP, potentially leading to credential theft or unauthorized access.
8.  The attacker uses the compromised credentials or SAML tokens to access sensitive resources within the organization's cloud environment, achieving data exfiltration or further lateral movement.

## Impact

Successful exploitation allows attackers to perform man-in-the-middle attacks and potentially gain unauthorized access to cloud resources by routing authentication through an attacker-controlled IdP. This can lead to data breaches, service disruption, and reputational damage. The addition and verification of custom domains are early indicators of such attacks and require immediate investigation to prevent further compromise.

## Recommendation

*   Deploy the Sigma rule `Entra ID Custom Domain Added or Verified` to your SIEM, using the `filebeat-*` and `logs-azure.auditlogs-*` indices, and tune it for your environment.
*   Review `azure.auditlogs.properties.initiated_by.user.userPrincipalName` and `ipAddress` to identify the user and source IP that initiated the domain addition or verification, as suggested in the rule's triage steps.
*   Monitor for subsequent `"Set domain authentication"` or `"Set federation settings on domain"` events following a domain addition or verification, as outlined in the rule's triage section.
*   Implement Privileged Identity Management (PIM) for Global Administrator roles to restrict domain management operations.
*   If an unauthorized domain addition is detected, immediately remove the unverified or verified domain using `Remove-MgDomain -DomainId "<domain>"`.
