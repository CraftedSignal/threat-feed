---
title: Entra ID OAuth Device Code Flow Phishing
slug: 2024-01-entra-device-code-phishing
description: Attackers are leveraging device code phishing to steal application access tokens from users of Entra ID OAuth applications, by tricking users into entering codes into attacker-controlled polling clients, leading to unauthorized access to cloud resources.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - entra-id
  - oauth
  - device-code-phishing
  - credential-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft 365
  - Microsoft Azure
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/identity/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
  - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://www.wiz.io/blog/recent-oauth-attacks-detection-strategies
rules:
  - title: Entra ID Device Code Flow with Multiple User Agents
    description: Detects Entra ID device code authentication flows where multiple user agents are observed within the same session, indicating potential device code phishing.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1528
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Device Code Flow with Multiple IPs
    description: Detects Entra ID device code authentication flows where multiple source IPs are observed within the same session, indicating potential device code phishing.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1528
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

Attackers are targeting Microsoft Entra ID OAuth workflows using device code phishing techniques. This involves tricking users into entering a device code into a malicious application or website controlled by the attacker. The attacker then uses this code to authenticate and gain unauthorized access to the user's account and associated cloud resources. This attack relies on the user's trust in the Microsoft login process and their unawareness of the attacker's involvement. Successful exploitation allows the attacker to bypass multi-factor authentication (MFA) and gain persistent access through stolen application access tokens. Volexity reported on Russian threat actors targeting Microsoft 365 OAuth workflows using device code phishing in April 2025. Defenders should monitor for unusual combinations of user agents and IP addresses in Entra ID sign-in logs.

## Attack Chain

1. The attacker sets up a malicious application or website that mimics a legitimate Microsoft login page.
2. The attacker sends a phishing email or message to the victim, enticing them to visit the malicious application or website.
3. The victim enters their credentials and is prompted to enter a device code.
4. Unbeknownst to the victim, the attacker uses the stolen credentials and device code within a polling client (e.g., a Python script) to initiate an OAuth flow.
5. The attacker's polling client receives an access token upon successful authentication.
6. The attacker uses the access token to access the victim's account and resources within the Entra ID environment.
7. The attacker may then perform various malicious activities such as reading emails, accessing files, or launching further attacks.
8. The attacker maintains persistence by using the stolen access token for as long as it remains valid.

## Impact

Successful device code phishing attacks can lead to significant data breaches and financial losses. An attacker can gain complete control over a user's account, allowing them to access sensitive information, steal data, or perform other malicious activities. Stolen access tokens can be used to bypass MFA, providing attackers with persistent access to the victim's resources. The number of victims can vary, but large-scale phishing campaigns can impact hundreds or thousands of users. Targeted sectors include organizations that heavily rely on Microsoft 365 and Azure services.

## Recommendation

*   Enable and configure the Azure logs integration to collect all sign-in logs from Entra ID as required by the rule `Entra ID OAuth Device Code Flow with Concurrent Sign-ins`.
*   Deploy the Sigma rule `Entra ID OAuth Device Code Flow with Concurrent Sign-ins` to detect device code authentication flows with multiple user agents within the same session.
*   Investigate sign-in logs for unusual combinations of user agents (e.g., browser and Python Requests) and IP addresses associated with device code authentication flows to identify potential phishing attempts, as mentioned in the rule description.
*   Implement Conditional Access policies that require device compliance checks and restrict access to trusted locations or devices only, to mitigate the risk of Primary Refresh Token abuse, as recommended in the rule's remediation steps.
