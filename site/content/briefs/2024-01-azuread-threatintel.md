---
title: Azure AD Threat Intelligence Detection
slug: 2024-01-azuread-threatintel
description: This brief focuses on detecting unusual user activity and sign-in patterns flagged by Azure AD Threat Intelligence, which may indicate stealthy attacks, persistence attempts, privilege escalation, or initial access.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - threat-intelligence
  - risk-detection
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#azure-ad-threat-intelligence-sign-in
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#azure-ad-threat-intelligence-user
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_threat_intel.yml
rules:
  - title: Azure AD Threat Intelligence Detection
    description: Detects Azure AD Threat Intelligence alerts indicating unusual user activity or known attack patterns.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - riskdetection
  - title: Azure AD Sign-in from Unusual Location
    description: Detects sign-ins from locations not typically accessed by the user.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078
    data_sources:
      - azure
      - audit
rules_count: 2
---

Azure AD Threat Intelligence identifies suspicious user activities that deviate from established patterns or align with known attack tactics. These alerts, surfaced within the Azure AD Identity Protection framework, are crucial for detecting stealthy maneuvers, persistence attempts, unauthorized privilege escalations, and initial access attempts. The alerts are triggered by unusual sign-ins, potentially originating from unfamiliar locations or devices. Defenders should prioritize investigation into these alerts as they can be indicative of compromised accounts or malicious actors attempting to gain unauthorized access to resources within the Azure environment. Successfully identifying and mitigating these threats prevents further lateral movement, data exfiltration, and potential damage to the organization.

## Attack Chain

1.  An attacker compromises user credentials through phishing, credential stuffing, or other means (Initial Access).
2.  The attacker attempts to sign in to Azure AD using the compromised credentials, potentially from an unusual location or device.
3.  Azure AD Threat Intelligence detects the unusual sign-in activity based on risk indicators and flags it as 'investigationsThreatIntelligence'.
4.  The attacker, if successful in the initial sign-in, attempts to access sensitive resources or applications within the Azure environment.
5.  The attacker may attempt to establish persistence by modifying user profiles or application settings.
6.  The attacker may attempt to escalate privileges by exploiting vulnerabilities or misconfigurations within the Azure environment.
7.  The attacker moves laterally to other resources and accounts.
8.  The attacker achieves their objective, such as data exfiltration or disruption of services.

## Impact

A successful attack targeting Azure AD can compromise user accounts and lead to unauthorized access to sensitive data and resources. The impact can range from data breaches and financial losses to reputational damage and disruption of business operations. Organizations relying heavily on Azure AD for identity and access management are particularly vulnerable. The number of affected users and the extent of the damage will depend on the attacker's objectives and the organization's security posture.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect 'investigationsThreatIntelligence' events within Azure AD risk detection logs (logsource: azure, service: riskdetection).
*   Investigate sessions flagged by the detection, correlating with other sign-in events from the same user to identify potential false positives or confirm malicious activity.
*   Implement multi-factor authentication (MFA) to mitigate the risk of compromised credentials and unauthorized sign-ins.
*   Review and enforce conditional access policies to restrict access based on location, device, and other risk factors.
