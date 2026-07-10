---
title: Entra ID Device Code Authentication Abuse via Malicious Broker Client
slug: 2024-11-entra-id-device-code-auth
description: Adversaries are abusing Entra ID device code authentication using a malicious broker client to bypass MFA and gain unauthorized access to Azure resources by compromising Primary Refresh Tokens (PRTs).
date: "2024-11-15T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra-id
  - device-code-authentication
  - prt
vendors:
  - Microsoft
products:
  - Azure
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://dirkjanm.io/assets/raw/Phishing%20the%20Phishing%20Resistant.pdf
  - https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in
  - https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
iocs:
  - type: uuid
    value: 29d9ed98-a469-4536-ade2-f981bc1d605e
  - type: url
    value: https://dirkjanm.io/assets/raw/Phishing%20the%20Phishing%20Resistant.pdf
  - type: url
    value: https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in
  - type: url
    value: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
ioc_counts:
  url: 3
  uuid: 1
rules:
  - title: Entra ID OAuth Device Code Grant by Microsoft Authentication Broker
    description: Detects device code authentication with a specific Azure broker client application ID, indicating potential abuse of Primary Refresh Tokens (PRTs).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Activity Logs Device Code Authentication with Broker Client
    description: Detects device code authentication with a specific Azure broker client application ID in activity logs, indicating potential abuse of Primary Refresh Tokens (PRTs).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - azure
rules_count: 2
---

Threat actors are exploiting the device code authentication flow in Entra ID to compromise Primary Refresh Tokens (PRTs) and bypass multi-factor authentication (MFA). This involves the use of a malicious or compromised broker client application with the ID `29d9ed98-a469-4536-ade2-f981bc1d605e`. By successfully authenticating with this broker client, attackers can obtain valid PRTs, which are then used to access Azure resources without triggering MFA. This technique allows them to circumvent Conditional Access policies that rely on device-based controls. Successful exploitation can lead to unauthorized access to sensitive data, lateral movement within the Azure environment, and potential data exfiltration. This activity is typically observed in Azure Sign-In logs and Activity logs.

## Attack Chain

1.  **Initial Compromise:** The attacker compromises user credentials via phishing or other means (not specified in source, but implied).
2.  **Device Code Authentication Initiation:** The attacker initiates the device code authentication flow using the compromised credentials and a malicious application.
3.  **Malicious Broker Client Application:** The attacker uses a broker client application with the specific application ID `29d9ed98-a469-4536-ade2-f981bc1d605e`.
4.  **Device Code Presentation:** The user is prompted to enter a code on a separate device to authenticate.
5.  **PRT Acquisition:** Upon successful device code authentication, the attacker obtains a valid Primary Refresh Token (PRT).
6.  **Bypass MFA & Conditional Access:** The PRT allows the attacker to bypass multi-factor authentication and Conditional Access policies that rely on device compliance.
7.  **Resource Access:** The attacker uses the PRT to access protected Azure resources and services without proper authorization.
8.  **Lateral Movement/Data Exfiltration:** The attacker moves laterally within the Azure environment or exfiltrates sensitive data, leveraging the unauthorized access gained through the compromised PRT.

## Impact

Successful exploitation allows attackers to bypass multi-factor authentication and gain unauthorized access to Azure resources, leading to potential data breaches and lateral movement within the cloud environment. The impact includes unauthorized access to sensitive data, circumvention of device-based Conditional Access controls, and the potential for data exfiltration. The number of affected users and the scope of data breaches depend on the permissions associated with the compromised accounts.

## Recommendation

*   Deploy the Sigma rule "Entra ID OAuth Device Code Grant by Microsoft Authentication Broker" to detect successful sign-ins using device code authentication with the specified broker client application ID in your Azure environment.
*   Investigate and revoke any Primary Refresh Tokens (PRTs) associated with the broker client application ID `29d9ed98-a469-4536-ade2-f981bc1d605e` where unauthorized access is suspected.
*   Monitor Azure Sign-In logs (`logs-azure.signinlogs-*`) and Activity logs (`logs-azure.activitylogs-*`) for device code authentication events (`azure.signinlogs.properties.authentication_protocol:deviceCode`) associated with the malicious broker client.
*   Implement Conditional Access policies that enforce device compliance checks and restrict access to trusted locations or devices to mitigate the risk of PRT abuse.
