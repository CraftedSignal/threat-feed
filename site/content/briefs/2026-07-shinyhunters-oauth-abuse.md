---
title: ShinyHunters OAuth Abuse Targeting SaaS Applications
slug: 2026-07-shinyhunters-oauth-abuse
description: ShinyHunters, and related threat actor Storm-3138, conducted campaigns between mid-2025 and mid-2026 by employing voice phishing, supply chain compromise, and misconfigured guest access to abuse trusted OAuth relationships in SaaS applications like Salesforce, leading to unauthorized access, data exfiltration, and persistence.
date: "2026-07-13T22:59:52Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ShinyHunters
tags:
  - oauth-abuse
  - saas
  - supply-chain
  - vishing
  - data-exfiltration
  - persistence
  - cloud
vendors:
  - Salesforce
  - Salesloft
  - Gainsight
  - Klue
products:
  - Salesforce
  - Salesforce Data Loader tool
  - Salesloft Drift
  - Gainsight-published applications
  - Klue
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: threat actors escalated into supply-chain-driven attacks targeting third-party SaaS vendors offering popular solutions that integrate with Salesforce, often using OAuth tokens.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: 'After users granted consent, these highly privileged OAuth applications enabled threat actors to perform API calls on behalf of the victim user, facilitating: Persistent access to Salesforce CRM data'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: attackers to obtain connection secrets used by downstream SaaS applications, enabling the use of OAuth tokens in multiple customer Salesforce instances.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The threat actors abused trusted OAuth relationships for unauthorized access, data exfiltration, and persistence.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Enumeration of Salesforce instances belonging to targeted organizations
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Threat actors exfiltrate data through sanctioned application access inherited from user privileges.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/
---

Microsoft Threat Intelligence has identified sophisticated campaigns conducted by the threat actor ShinyHunters, with overlapping tradecraft observed between mid-2025 and mid-2026. These campaigns also included activity attributed to Storm-3138. The threat actors primarily targeted customer SaaS-based applications, such as Salesforce instances, leveraging a combination of voice phishing (vishing), supply chain compromise, and the exploitation of misconfigured guest access. The primary objective was to abuse trusted OAuth relationships to gain unauthorized access, establish persistence, and exfiltrate sensitive data at scale. This activity highlights a shift towards exploiting legitimate application functionality and integrations rather than traditional malware deployment, making detection challenging as malicious actions often appear indistinguishable from normal user behavior within the SaaS ecosystem.

## Attack Chain

1. Threat actors initiate voice phishing (vishing) attacks, impersonating IT support personnel, to socially engineer employees into authorizing malicious applications.
2. Victims are guided through an OAuth consent workflow, granting an attacker-controlled application (e.g., disguised as a Salesforce Data Loader tool) highly privileged access.
3. The malicious OAuth application performs API calls on behalf of the victim user, enabling enumeration of Salesforce instances and persistent access to CRM data.
4. Attackers compromise third-party SaaS vendors (e.g., Salesloft in August 2025, Gainsight in November 2025, Klue in June 2026), obtaining connection secrets or OAuth tokens.
5. Compromised credentials or OAuth tokens are used to leverage trusted external connections, maintaining persistent API access to multiple Salesforce customer instances.
6. Attackers identify and exploit misconfigured guest-user permissions within Salesforce Aura endpoints, granting unauthenticated access to Aura framework functionality.
7. GraphQL-based Aura requests are chained to systematically query and retrieve large volumes of sensitive CRM data, bypassing standard record-retrieval limitations.
8. Threat actors exfiltrate sensitive CRM records, including accounts, contacts, and service case data, through sanctioned application access or abused guest permissions.

## Impact

The observed campaigns resulted in significant data exfiltration, primarily of sensitive CRM records, including accounts, contacts, and service case data, affecting numerous organizations across retail, education, and manufacturing sectors. Threat actors achieved quiet persistence within targeted SaaS environments, making malicious activity difficult to distinguish from legitimate operations. The abuse of trusted OAuth relationships allowed attackers to access and exfiltrate data at scale, bypassing traditional authentication-focused detections. The broad scope and the ability to operate within trusted workflows posed a high-impact risk to sensitive data and downstream SaaS ecosystems.

## Recommendation

* Enable Salesforce Shield: Event Monitoring and integrate with Microsoft Defender for Cloud Apps to gain near-real-time visibility into Salesforce security and activity events.
* Regularly review and audit all OAuth-connected applications within your SaaS environments, paying close attention to application identity, granted OAuth scopes, and activity context.
* Implement strict validation processes for all third-party integrations and monitor their activity for anomalies, particularly for vendors like Salesloft, Gainsight, and Klue that have been previously targeted.
* Conduct regular audits of guest access configurations in Salesforce and other SaaS platforms to ensure proper permissions are enforced and to prevent unauthorized data access via endpoints like Salesforce Aura.
* Deploy security solutions that provide expanded identity, session, and API activity context within Salesforce and other SaaS applications to improve correlation and identification of suspicious activity as detected by Microsoft Defender for Cloud Apps.
