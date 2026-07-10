---
title: AzureHound Reconnaissance Activity in Azure AD
slug: 2024-01-azurehound-recon
description: Detection of the AzureHound User-Agent in Azure AD logs indicates potential reconnaissance activity by adversaries mapping the Azure AD infrastructure for vulnerabilities.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azuread
  - reconnaissance
  - azurehound
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Microsoft Graph
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1526
    technique_name: Cloud Service Discovery
references:
  - https://github.com/SpecterOps/AzureHound
  - https://splunkbase.splunk.com/app/3110
  - https://splunk.github.io/splunk-add-on-for-microsoft-cloud-services/Install/
rules:
  - title: Azure AD AzureHound UserAgent Detected
    description: Detects the presence of the default AzureHound user-agent string within Microsoft Graph Activity logs and NonInteractive SignIn Logs, indicating potential reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
      - T1526
    data_sources:
      - webserver
      - azure
  - title: Azure AD NonInteractive Sign-in with AzureHound
    description: Detects non-interactive sign-ins using AzureHound, which might indicate automated reconnaissance activities.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
      - T1526
    data_sources:
      - webserver
      - azure
rules_count: 2
---

This threat brief focuses on the detection of the AzureHound User-Agent within Azure Active Directory (Azure AD) environments. AzureHound is a tool utilized to gather comprehensive information about Azure AD configurations. While legitimate security professionals often use it for auditing, malicious actors can leverage it for reconnaissance. By mapping the Azure AD infrastructure, attackers can identify potential weaknesses and targets for exploitation. This detection is crucial because it signals potential unauthorized reconnaissance, allowing defenders to proactively address security threats before further compromise occurs. The activity is detected within Microsoft Graph Activity Logs and NonInteractiveUserSignInLogs.

## Attack Chain

1.  **Initial Access:** Attacker gains initial access to an account or service principal within the Azure AD environment (potentially through compromised credentials or misconfiguration).
2.  **Authentication:** The attacker authenticates to Azure AD using the compromised account or service principal.
3.  **Graph API Enumeration:** Attacker uses AzureHound, configured with the compromised credentials, to send a series of requests to the Microsoft Graph API.
4.  **User and Group Discovery:** AzureHound enumerates users, groups, and their associated attributes within the Azure AD tenant.
5.  **Application Registration Discovery:** The tool identifies application registrations, their permissions, and related configurations.
6.  **Role Assignment Enumeration:** AzureHound retrieves information about role assignments, identifying privileged accounts and potential escalation paths.
7.  **Data Collection and Analysis:** The attacker gathers the collected data from the Graph API requests and analyzes it to identify vulnerabilities, misconfigurations, and potential targets for further exploitation.
8.  **Lateral Movement/Privilege Escalation:** Based on the information gathered, the attacker attempts to move laterally within the Azure AD environment or escalate privileges to gain control over critical resources.

## Impact

A successful AzureHound reconnaissance can expose sensitive information about the Azure AD environment, including user accounts, group memberships, application registrations, and role assignments. This information can be used by attackers to identify vulnerabilities, misconfigurations, and potential targets for further exploitation. The number of victims and specific sectors targeted depend on the attacker's objectives. If the attack succeeds, it could lead to data breaches, unauthorized access to critical resources, and ultimately, significant financial and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD AzureHound UserAgent Detected` to your SIEM and tune for your environment, focusing on the `MicrosoftGraphActivityLogs` and `NonInteractiveUserSignInLogs` to detect AzureHound activity.
*   Investigate any detected instances of the AzureHound User-Agent to determine the source and purpose of the activity, referencing the `src` and `user` fields in the Sigma rule output.
*   Review and harden Azure AD configurations based on the information potentially gathered by AzureHound, such as overly permissive application permissions or exposed credentials.
*   Monitor for unusual activity following the detection of AzureHound, such as attempts to access sensitive resources or escalate privileges, using the analytic story "Azure Active Directory Privilege Escalation".
