---
title: Entra ID Concurrent Sign-in with Suspicious Properties
slug: 2024-01-30-entra-id-concurrent-signin
description: This rule identifies concurrent Azure sign-in events for the same user from multiple sources, where at least one authentication event exhibits suspicious properties associated with DeviceCode and OAuth phishing, potentially indicating refresh token theft.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra-id
  - credential-access
  - phishing
vendors:
  - Microsoft
products:
  - Azure Entra ID
  - Microsoft Graph
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/identity/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
  - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
rules:
  - title: Entra ID Concurrent Sign-in with Suspicious Properties
    description: Detects concurrent Azure sign-in events with suspicious properties indicative of OAuth phishing or device code abuse.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1528
      - T1566.002
    data_sources:
      - webserver
      - azure
  - title: Entra ID Sign-in from Multiple IPs
    description: Detects sign-in events from multiple distinct IP addresses for the same user account within a short period, potentially indicating account compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078
      - T1550
    data_sources:
      - webserver
      - azure
rules_count: 2
---

This detection identifies suspicious concurrent sign-in activity within an Azure Entra ID environment. Specifically, it focuses on scenarios where the same user account initiates sign-in events from multiple source IP addresses within a short timeframe (60 minutes). The rule further refines this detection by flagging instances where at least one of these concurrent sign-in attempts exhibits characteristics associated with Device Code authentication or access to Microsoft Graph via Visual Studio Code, both of which can be exploited in OAuth phishing attacks to steal refresh tokens. This technique allows attackers to bypass multi-factor authentication (MFA) and gain unauthorized access to Azure resources. The rule leverages Azure sign-in logs and requires the Azure logs integration to be enabled and configured to collect all logs, including sign-in logs from Entra.

## Attack Chain

1.  **Initial Access:** The attacker initiates a phishing campaign targeting users with access to Azure resources (T1566.002). The phishing email contains a link that directs the user to a malicious OAuth application consent page.
2.  **Credential Access:** The user, believing the consent page is legitimate, grants the malicious application access to their account (T1528). The attacker obtains a refresh token upon successful consent.
3.  **Defense Evasion:** The attacker uses the stolen refresh token to authenticate to Azure services, bypassing MFA if the token has not been revoked (T1550.001).
4.  **Valid Accounts:** The attacker leverages the valid user account and stolen refresh token to access cloud resources (T1078.004).
5.  **Use Alternate Authentication Material:** The attacker uses the refresh token to request access tokens for various Azure services without needing to re-authenticate or trigger MFA (T1550.001).
6.  **Persistence:** The attacker maintains persistent access to the Azure environment as long as the refresh token remains valid and is not revoked by the legitimate user or Azure administrator.
7.  **Privilege Escalation (Potential):** Depending on the permissions associated with the compromised account, the attacker may attempt to escalate privileges within the Azure environment.
8.  **Impact:** The attacker gains unauthorized access to sensitive data, applications, or infrastructure within the Azure environment, potentially leading to data exfiltration, service disruption, or financial loss.

## Impact

Successful exploitation can lead to unauthorized access to sensitive cloud resources, potentially affecting any organization leveraging Azure Entra ID for identity and access management. The number of victims depends on the scope of the phishing campaign and the level of access granted to compromised accounts. This attack can result in data breaches, financial losses, and reputational damage. The primary targets are organizations that rely heavily on Azure services and have not implemented adequate security measures to prevent OAuth phishing attacks or detect refresh token theft.

## Recommendation

*   Deploy the provided Sigma rule `Entra ID Concurrent Sign-in with Suspicious Properties` to your SIEM to detect potential refresh token theft attempts (see `rules` section).
*   Review and harden Conditional Access policies to restrict access to trusted locations or devices only, mitigating the risk of future PRT abuse, as mentioned in the references and triage notes.
*   Configure alerts for unusual sign-in patterns or device code authentication attempts from unexpected locations or devices, improving early detection of similar threats, referencing the triage notes.
*   Ensure the Azure logs integration is enabled and configured to collect all logs, including sign-in logs from Entra, as outlined in the `setup` section.
*   Investigate any alerts generated by the Sigma rule by reviewing the sign-in logs, assessing the context and reputation of the source.ip address, and checking for any recent changes or anomalies in the user's account settings or permissions.
