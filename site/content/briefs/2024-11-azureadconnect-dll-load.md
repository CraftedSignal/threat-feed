---
title: Untrusted DLL Loaded by Azure AD Connect Authentication Agent
slug: 2024-11-azureadconnect-dll-load
description: The loading of an untrusted DLL by the Azure AD Connect Authentication Agent, potentially indicating credential access attempts via the Pass-through Authentication service, is detected by this rule.
date: "2024-11-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - dll-side-loading
  - azure-ad-connect
vendors:
  - Microsoft
products:
  - Azure AD Connect Authentication Agent
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://blog.xpnsec.com/azuread-connect-for-redteam/
  - https://medium.com/@breakingmhet/detect-azure-pass-through-authentication-abuse-azure-hybrid-environments-ed4274784252
  - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication
rules:
  - title: Untrusted DLL Loaded by Azure AD Connect Authentication Agent
    description: Detects the loading of an untrusted DLL by the Azure AD Connect Authentication Agent, which may indicate an attempt to persist or intercept credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - image_load
      - windows
  - title: Azure AD Connect Authentication Agent Loading DLL from Suspicious Path
    description: Detects Azure AD Connect Authentication Agent loading a DLL from a suspicious path, potentially indicating DLL side-loading or compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - image_load
      - windows
rules_count: 2
---

The Azure AD Connect Authentication Agent facilitates pass-through authentication (PTA) in hybrid environments. Attackers may attempt to load malicious DLLs into the `AzureADConnectAuthenticationAgentService.exe` process to intercept or persist credentials. This involves placing an untrusted DLL in a location where the service will load it, such as a directory with weak permissions or through DLL side-loading. Successful exploitation allows attackers to capture user credentials as they are processed by the PTA service, potentially leading to domain compromise. This activity specifically targets systems utilizing Azure AD Connect with PTA enabled. Defenders should monitor for unexpected DLL loads by the Azure AD Connect Authentication Agent to identify and prevent credential access attempts.

## Attack Chain

1.  An attacker gains initial access to a system hosting the Azure AD Connect Authentication Agent.
2.  The attacker identifies a location where they can place a malicious DLL that the `AzureADConnectAuthenticationAgentService.exe` process will load, such as a directory with weak permissions or a location susceptible to DLL side-loading.
3.  The attacker places a malicious DLL (e.g., `evil.dll`) into the identified location.
4.  The `AzureADConnectAuthenticationAgentService.exe` process is started or restarted.
5.  The `AzureADConnectAuthenticationAgentService.exe` process loads the malicious DLL (`evil.dll`).
6.  The malicious DLL intercepts or captures credentials as they are processed by the PTA service.
7.  The attacker exfiltrates the captured credentials.
8.  The attacker uses the stolen credentials to gain unauthorized access to other systems or resources.

## Impact

Successful exploitation allows attackers to intercept credentials handled by the Azure AD Connect Authentication Agent. This can lead to the compromise of user accounts and the ability to move laterally within the environment. Organizations using Azure AD Connect with Pass-through Authentication are at risk. The impact includes potential data breaches, unauthorized access to sensitive information, and domain compromise.

## Recommendation

*   Implement the Sigma rule `Untrusted DLL Loaded by Azure AD Connect Authentication Agent` to detect the loading of untrusted DLLs by the Azure AD Connect Authentication Agent service in your environment.
*   Monitor process creation events for `AzureADConnectAuthenticationAgentService.exe` loading DLLs outside of the standard Microsoft directories, as defined in the Sigma rule.
*   Enable Sysmon Event ID 7 (Image Loaded) logging to provide the necessary data for the Sigma rule to function effectively.
*   Restrict write access to the Azure AD Connect Authentication Agent directories to prevent unauthorized DLL placement.
*   Review administrative access to the PTA host to prevent unauthorized modifications.
