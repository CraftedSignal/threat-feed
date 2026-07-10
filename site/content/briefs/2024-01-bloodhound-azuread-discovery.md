---
title: BloodHound Suite User-Agent Detected in Entra ID Sign-ins
slug: 2024-01-bloodhound-azuread-discovery
description: Detection of BloodHound tools like AzureHound and SharpHound being used to enumerate Microsoft Entra ID and Microsoft 365 environments, potentially indicating reconnaissance activity by red teams or malicious actors.
date: "2024-01-09T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azuread
  - bloodhound
  - enumeration
  - discovery
vendors:
  - Microsoft
products:
  - Microsoft Azure
  - Microsoft 365
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1201
    technique_name: Password Policy Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://specterops.io/bloodhound-overview/
  - https://github.com/SpecterOps/AzureHound
  - https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/
rules:
  - title: Entra ID Sign-in BloodHound User-Agent Detected
    description: Detects BloodHound-like user agents in Azure AD sign-in logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Graph API BloodHound Enumeration
    description: Detects BloodHound-like user agents accessing Graph API endpoints associated with enumeration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - webserver
      - linux
  - title: Microsoft 365 Audit Logs BloodHound Detection
    description: Detects BloodHound-like user agents in Microsoft 365 Audit Logs
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - webserver
      - windows
rules_count: 3
---

This threat brief focuses on the detection of reconnaissance activities within Microsoft Azure and Microsoft 365 environments through the use of BloodHound tools. Specifically, it addresses the use of AzureHound, SharpHound, and BloodHound by adversaries or red teams to map out users, groups, roles, applications, and access relationships within Microsoft Entra ID (Azure AD). The Elastic detection rule published on 2026-04-10 identifies activity based on the presence of suspicious user agent strings (e.g., `azurehound/`, `sharphound/`, `bloodhound/`) in various Azure and M365 logs. This technique allows attackers to gain a comprehensive understanding of the target environment's structure and potential vulnerabilities, often as a precursor to further exploitation. The scope of the detection includes Azure Graph API Activity Logs, Microsoft 365 Audit Logs, Entra ID Sign-in Logs, Entra ID Audit Logs, and Azure Activity Logs.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to a compromised account or obtains valid credentials.
2. **Tool Deployment:** The attacker deploys a BloodHound tool (AzureHound, SharpHound) on a compromised system or uses a cloud-based instance.
3. **Authentication:** The tool authenticates to Azure AD using the compromised credentials or a service principal.
4. **Enumeration:** The BloodHound tool begins enumerating users, groups, roles, applications, and access relationships using the Microsoft Graph API. This involves sending numerous API requests.
5. **Data Collection:** The tool collects data about the Azure AD environment, including user details, group memberships, role assignments, and application permissions. API endpoints such as `/v1.0/users`, `/v1.0/groups`, and `/v1.0/organization` are accessed.
6. **Data Analysis:** The collected data is analyzed to identify potential attack paths, such as privileged accounts, weak access controls, and lateral movement opportunities.
7. **Privilege Escalation (Potential):** Based on the identified attack paths, the attacker attempts to escalate privileges or gain access to sensitive resources.
8. **Lateral Movement (Potential):** Using compromised credentials or service principals, the attacker moves laterally within the Azure AD environment to access additional resources and data.

## Impact

Successful enumeration using BloodHound tools can expose the entire structure of an Azure AD environment, leading to significant security risks. This includes the potential for privilege escalation, lateral movement, and data exfiltration. Attackers can leverage the gathered information to identify critical assets, high-value accounts, and vulnerable configurations, enabling them to launch targeted attacks. The impact could affect organizations of any size relying on Azure AD and Microsoft 365 for identity management and cloud services. If exploited, attackers can pivot to critical infrastructure and cause severe business disruptions.

## Recommendation

*   Deploy the Sigma rule "Entra ID Sign-in BloodHound Suite User-Agent Detected" to your SIEM and tune for your environment to detect enumeration attempts.
*   Enable verbose audit logging on Azure AD and Microsoft 365 services to capture detailed information about API requests, sign-in attempts, and user activity.
*   Review the false positives outlined in the overview section of the rule and implement appropriate allowlist conditions based on `app_id`, user context or source address.
*   Implement Conditional Access policies in Azure AD to enforce multi-factor authentication (MFA) for all users, especially for privileged accounts and API access.
*   Regularly review and reduce excessive privileges assigned to users and service principals to minimize the impact of potential breaches.
