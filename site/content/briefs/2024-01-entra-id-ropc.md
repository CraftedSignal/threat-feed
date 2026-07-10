---
title: Entra ID Unusual ROPC Login Attempt
slug: 2024-01-entra-id-ropc
description: Detects unusual resource owner password credential (ROPC) login attempts by a user principal in Microsoft Entra ID, potentially indicating account compromise or password spraying.
date: "2024-01-17T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - azure
  - entra-id
  - ropc
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign
  - https://dirkjanm.io/assets/raw/Finding%20Entra%20ID%20CA%20Bypasses%20-%20the%20structured%20way.pdf
  - https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc
rules:
  - title: Entra ID OAuth ROPC Grant Login Detected
    description: Detects successful ROPC login attempts in Entra ID sign-in logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Entra ID OAuth ROPC Login from Unusual Client IP
    description: Detects ROPC login attempts from client IPs that have not been seen in the last 10 days.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies unusual Resource Owner Password Credentials (ROPC) login attempts within Microsoft Entra ID. ROPC is a legacy OAuth 2.0 flow where applications obtain tokens by directly providing user credentials, a method less secure than modern alternatives. Adversaries exploit ROPC to bypass multi-factor authentication (MFA) and gain unauthorized access to user accounts. The rule specifically focuses on detecting first-time ROPC usage by a user principal within a 10-day window, indicating potential enumeration, password spraying, or use of compromised credentials. Successful ROPC logins without MFA are a red flag. This activity is typically associated with account takeover attempts.

## Attack Chain

1. **Initial Access:** An attacker gains initial access by obtaining valid user credentials through phishing, password spraying, or credential stuffing.
2. **Bypass MFA:** The attacker leverages the ROPC flow to bypass MFA, as ROPC does not inherently require or support it.
3. **Application Enumeration:** The attacker uses tools like TeamFiltration or custom scripts to enumerate available applications and resources accessible with the compromised account.
4. **Token Acquisition:** The attacker's application or script requests an access token from Entra ID using the compromised credentials and the ROPC grant type.
5. **Resource Access:** With a valid access token, the attacker accesses sensitive resources such as Exchange Online, SharePoint, or Teams, depending on the permissions granted to the application and user.
6. **Lateral Movement:** The attacker uses the initial access to move laterally within the Entra ID environment, targeting additional user accounts or resources.
7. **Data Exfiltration:** The attacker exfiltrates sensitive data from accessed resources, such as emails, documents, or application data.

## Impact

Successful exploitation allows attackers to gain unauthorized access to user accounts and sensitive resources within the Microsoft Entra ID environment. This can lead to data breaches, financial loss, and reputational damage. The ROPC flow, when abused, circumvents MFA protections, increasing the risk of successful account takeover. Organizations may experience data exfiltration, business email compromise, or disruption of cloud services.

## Recommendation

*   Deploy the Sigma rule "Entra ID OAuth ROPC Grant Login Detected" to your SIEM and tune for your environment to identify unusual ROPC login attempts (see rule below).
*   Review the `azure.signinlogs.properties.user_principal_name` field from the logs to identify the users involved in ROPC login attempts.
*   Investigate the source of the ROPC login attempt, including the application (`azure.signinlogs.properties.app_display_name`) and IP address (`azure.signinlogs.properties.client_ip`) by enabling Azure Sign-In Logs.
*   Enforce multi-factor authentication (MFA) for all users and applications, and restrict the use of ROPC where possible.
*   Monitor for suspicious activity, such as unusual login locations or access to sensitive resources.
