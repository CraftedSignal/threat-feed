---
title: Spoofing AD FS Signing Logs via Azure AD Hybrid Health Service
slug: 2024-01-23-azuread-adfs-spoofing
description: A threat actor can create a new, rogue AD Health ADFS service within Azure and then create a fake server instance, which can be leveraged to spoof AD FS signing logs without compromising on-prem AD FS servers.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - azure
  - adfs
  - defense-impairment
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - AD FS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://o365blog.com/post/hybridhealthagent/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_new_server.yml
rules:
  - title: Azure AD Hybrid Health AD FS New Server Creation
    description: Detects the creation of a new AD FS server instance within the Azure AD Hybrid Health Service via Azure Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1578
    data_sources:
      - azure
      - activitylogs
  - title: Azure AD Hybrid Health Service Modification
    description: Detects modifications to the Azure AD Hybrid Health Service, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1578
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

This threat involves the creation of a rogue AD FS service instance within the Azure AD Hybrid Health Service to spoof AD FS signing logs. The attacker leverages the Azure AD Hybrid Health Service to create a new AD FS service and adds a fake server instance. This method allows the attacker to manipulate AD FS logging information without needing to compromise an on-premises AD FS server. The attack can be performed programmatically through HTTP requests to Azure, making it scalable and difficult to trace back to traditional on-premises attack vectors. This technique is particularly concerning because it undermines the integrity of AD FS logs, a crucial component for security monitoring and incident response.

## Attack Chain

1.  **Compromise Azure Account:** The attacker gains access to an Azure account, potentially through stolen credentials or exploiting a vulnerability.
2.  **Provision Rogue AD Health Service:** The attacker programmatically provisions a new AD Health Service within the compromised Azure environment, specifically targeting AD FS.
3.  **Create Fake Server Instance:** Within the newly created AD Health Service, the attacker creates a fake server instance, mimicking a legitimate AD FS server. The `ResourceId` will contain `AdFederationService`.
4.  **Manipulate Logs:** Using the fake server instance, the attacker injects or alters AD FS signing logs, creating a false narrative of user authentication events.
5.  **Impersonate Users/Bypass Authentication:** The attacker uses the manipulated logs to impersonate legitimate users or bypass authentication controls in applications relying on AD FS.
6.  **Lateral Movement/Privilege Escalation:** Using the falsely acquired credentials or authentication tokens, the attacker moves laterally within the network, escalating privileges to access sensitive resources.
7.  **Data Exfiltration/System Compromise:** The attacker exfiltrates sensitive data or gains control over critical systems using the compromised accounts and manipulated logs.

## Impact

Successful exploitation allows attackers to spoof AD FS signing logs, potentially leading to unauthorized access, data breaches, and system compromise. The compromised logs can be used to cover the attacker's tracks, making detection and incident response more difficult. Organizations relying on Azure AD Hybrid Health for AD FS monitoring are at risk of having their security posture undermined. The number of potential victims is substantial, as many organizations use AD FS for authentication and rely on its logs for security monitoring.

## Recommendation

*   Deploy the Sigma rule `Azure Active Directory Hybrid Health AD FS New Server` to your SIEM to detect the creation of new AD FS server instances within the Azure AD Hybrid Health Service. Tune the rule for your environment to minimize false positives.
*   Monitor Azure Activity Logs for any unusual activity related to the `Microsoft.ADHybridHealthService` resource provider and the `Microsoft.ADHybridHealthService/services/servicemembers/action` operation, specifically the `Administrative` category.
*   Review and validate all AD FS server instances registered within the Azure AD Hybrid Health Service to ensure their legitimacy.
*   Implement multi-factor authentication (MFA) for all Azure accounts to prevent unauthorized access and mitigate the risk of initial compromise.
