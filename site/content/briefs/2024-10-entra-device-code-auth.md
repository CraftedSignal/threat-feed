---
title: Entra ID OAuth Device Code Grant by Unusual User
slug: 2024-10-entra-device-code-auth
description: An attacker uses device code authentication in Entra ID to phish users and steal access tokens, leading to unauthorized access and potential defense evasion.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra-id
  - device-code
  - phishing
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://aadinternals.com/post/phishing/
  - https://www.blackhillsinfosec.com/dynamic-device-code-phishing/
  - https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
  - https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
rules:
  - title: Entra ID Device Code Authentication Success
    description: Detects successful Entra ID device code authentication events.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
      - T1566.002
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Device Code Authentication from Unusual Location
    description: Detects Entra ID device code authentication events from unusual geographic locations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
      - T1566.002
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

The "Entra ID OAuth Device Code Grant by Unusual User" rule identifies the first instance of a user authenticating via the DeviceCode authentication protocol. This authentication workflow, intended for devices without keyboards, can be abused by attackers to phish users and steal access tokens, leading to unauthorized access. The rule focuses on detecting new users leveraging this flow, specifically within Entra ID environments. The campaign leverages the device code flow, a feature intended for devices without browsers or input devices, to trick users into granting access to malicious applications. Observed activity includes authentication events indicating successful device code flows, potentially bypassing conditional access policies. This poses a risk to organizations by enabling unauthorized access to cloud resources.

## Attack Chain

1.  Attacker registers a malicious application within Entra ID.
2.  Attacker crafts a phishing email with a link prompting the user to visit a Microsoft login page and enter a provided code, initiating the Device Code flow (T1566.002).
3.  User, believing the prompt is legitimate, enters the code on the Microsoft login page.
4.  The malicious application receives an access token after the user authenticates via the device code flow (T1550.001).
5.  The attacker uses the stolen access token to access the user's cloud resources (T1078.004).
6.  The attacker may attempt to bypass MFA or conditional access policies, depending on configuration.
7.  The attacker then uses the access to move laterally within the cloud environment and exfiltrate data.

## Impact

Successful exploitation can lead to unauthorized access to sensitive cloud resources, data exfiltration, and further compromise of the Entra ID environment. The initial report indicates that multiple Russian threat actors are targeting Microsoft Device Code Authentication. This technique can potentially affect any organization using Microsoft Entra ID, and successful attacks can lead to significant data breaches and financial losses.

## Recommendation

*   Deploy the Sigma rule provided to detect unusual DeviceCode authentication events in your Entra ID environment and tune for your environment.
*   Review the application IDs excluded in the query to determine if they are expected within your environment.
*   Review `azure.signinlogs.properties.applied_conditional_access_policies` and `azure.signinlogs.properties.conditional_access_status` to determine if MFA or conditional access policies were enforced or bypassed during Device Code authentication events, and investigate any bypasses.
*   Limit DeviceCode authentication to approved users and applications via conditional access policies as described in the Microsoft documentation.
*   Enforce stricter MFA policies for sensitive accounts.
