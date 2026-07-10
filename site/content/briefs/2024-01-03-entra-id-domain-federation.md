---
title: Entra ID Domain Federation Configuration Change
slug: 2024-01-03-entra-id-domain-federation
description: Adversaries with Global Administrator or Domain Administrator privileges may add a custom domain, verify ownership, and configure it to federate authentication with an attacker-controlled identity provider, allowing token forgery and bypassing MFA and conditional access policies for persistent, stealthy access to victim tenants.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra-id
  - domain-federation
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29
  - https://learn.microsoft.com/en-us/graph/api/domain-post-federationconfiguration
  - https://medium.com/tenable-techblog/roles-allowing-to-abuse-entra-id-federation-for-persistence-and-privilege-escalation-df9ca6e58360
  - https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/
  - https://techcommunity.microsoft.com/blog/microsoft-entra-blog/understanding-and-mitigating-golden-saml-attacks/4418864
rules:
  - title: Entra ID Domain Federation Configuration Change
    description: Detects when domain federation settings are configured or modified in an Entra ID tenant via the Microsoft Graph API.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1484.002
      - T1556.007
    data_sources:
      - audit
      - azure
  - title: Entra ID Domain Added
    description: Detects when a new domain is added to Entra ID which can be a precursor to domain federation attacks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1484.002
      - T1556.007
    data_sources:
      - audit
      - azure
  - title: Entra ID Domain Verification
    description: Detects when a domain is verified in Entra ID which often follows the addition of an unverified domain in preparation for domain federation attacks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1484.002
      - T1556.007
    data_sources:
      - audit
      - azure
rules_count: 3
---

This threat brief focuses on the detection of malicious domain federation modifications within Microsoft Entra ID tenants. Attackers who have obtained Global Administrator or Domain Administrator privileges can exploit this functionality to establish persistent access. This involves adding a custom domain, verifying its ownership, and then configuring it to federate authentication with an identity provider controlled by the attacker. Once successfully federated, the attacker can forge SAML or WS-Federation tokens. This enables them to authenticate as any user within the compromised domain, effectively bypassing multi-factor authentication (MFA) and conditional access policies. This technique, known as Golden SAML, has been observed in campaigns such as the SolarWinds attack attributed to UNC2452 (APT29). Defenders must monitor for unauthorized domain federation activities to prevent persistent compromise.

## Attack Chain

1. **Initial Compromise:** The attacker gains initial access and escalates privileges to either Global Administrator or Domain Administrator within the Entra ID tenant.
2. **Add Unverified Domain:** The attacker adds a custom domain to the Entra ID tenant using the Microsoft Graph API, which is initially in an unverified state.
3. **Verify Domain Ownership:** The attacker verifies ownership of the newly added domain, often by adding a DNS TXT record.
4. **Set Domain Authentication:** The attacker sets the domain authentication type to federated using the `Set domain authentication` action. This action initiates the domain federation process.
5. **Set Federation Settings:** The attacker configures federation settings on the domain, pointing to an attacker-controlled identity provider (IdP). The `Set federation settings on domain` event will correlate to the "Set domain authentication" via the `correlation_id` field.
6. **Token Forgery:** The attacker forges SAML or WS-Federation tokens using the attacker-controlled IdP to impersonate any user within the federated domain.
7. **Access Resources:** The attacker uses the forged tokens to authenticate to various resources within the Entra ID tenant, bypassing MFA and conditional access policies.
8. **Persistent Access:** The attacker maintains persistent access to the Entra ID tenant by continuously generating valid tokens as needed, allowing them to conduct reconnaissance, exfiltrate data, or perform other malicious activities.

## Impact

Successful exploitation of domain federation vulnerabilities can lead to a complete compromise of the Entra ID tenant. Attackers can gain unauthorized access to sensitive data, applications, and resources. The SolarWinds attack demonstrated the potential for widespread supply chain compromise and data exfiltration. The lack of visibility into token forgery makes this attack particularly stealthy and difficult to detect. If successful, attackers can maintain persistent access for extended periods, causing significant financial and reputational damage.

## Recommendation

*   Deploy the Sigma rule "Entra ID Domain Federation Configuration Change" to your SIEM and tune for your environment to detect unauthorized domain federation changes.
*   Enable Azure integration with Microsoft Entra ID Audit Logs data stream and ingest into your Elastic Stack deployment as required by the Sigma rule.
*   Review and restrict who has Domain Administrator or Global Administrator roles using Privileged Identity Management (PIM) as mentioned in the rule documentation.
*   Implement alerts on domain management operations and restrict domain federation changes via conditional access policies as mentioned in the rule documentation.
*   If unauthorized domain federation changes are detected, follow the response and remediation steps outlined in the rule documentation, including removing the federation configuration and revoking active sessions.
*   Query the Graph API to retrieve the actual federation configuration details, since they are not logged in the audit event: `Get-MgDomainFederationConfiguration -DomainId "<domain>"`.
