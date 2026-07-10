---
title: Azure AD Service Principal Credential Addition
slug: 2024-01-azuread-service-principal-credential-add
description: Detection of new credentials added to Azure AD Service Principals and Applications via monitoring of the 'Update application*Certificates and secrets management' operation, potentially indicating persistence or privilege escalation attempts.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - persistence
  - privilege-escalation
  - cloud
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://attack.mitre.org/techniques/T1098/001/
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT501/AZT501-2/
  - https://hausec.com/2021/10/26/attacking-azure-azure-ad-part-ii/
  - https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html
  - https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT405/AZT405-3/
rules:
  - title: Azure AD Service Principal New Client Credentials - Sigma
    description: Detects the addition of new credentials to Service Principals and Applications in Azure AD via the Azure AD AuditLogs.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - audit
      - azure
      - azuread
  - title: Azure AD Service Principal Credential Modification by Uncommon User
    description: Detects Service Principal credential modifications performed by user accounts not typically associated with such changes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - audit
      - azure
      - azuread
rules_count: 2
---

This threat brief focuses on the malicious addition of new credentials to Service Principals and Applications within Azure Active Directory (Azure AD). The activity is identified by monitoring the "Update application*Certificates and secrets management" operation within Azure AD AuditLogs. This behavior is significant because adversaries can use it to establish persistence, escalate privileges, and gain unauthorized access to sensitive resources within the Azure environment. Attackers, including groups such as NOBELIUM and Scattered Lapsus$ Hunters, may target service principals to maintain long-term access to compromised environments. Defenders must monitor this activity to identify and prevent potential breaches. This activity is logged and auditable within Azure AD, providing defenders with an opportunity to detect and respond to this specific tactic.

## Attack Chain

1. The attacker gains initial access to an Azure AD account with sufficient privileges to modify Service Principals or Applications.
2. The attacker identifies a target Service Principal or Application within the Azure AD environment.
3. The attacker navigates to the Azure portal or uses Azure CLI/PowerShell to access the target's configuration.
4. The attacker adds a new client secret or certificate credential to the Service Principal or Application using the "Update application*Certificates and secrets management" operation.
5. Azure AD logs the credential modification event in the AuditLogs, specifically under the "Update application*Certificates and secrets management" operation.
6. The attacker uses the newly added credentials to authenticate as the Service Principal, bypassing existing security controls.
7. The attacker leverages the Service Principal's permissions to access sensitive resources, such as databases, storage accounts, or other applications.
8. The attacker maintains persistent access to the environment, potentially exfiltrating data, deploying malware, or causing disruption.

## Impact

Successful exploitation allows attackers to maintain persistent access to the Azure AD environment, potentially leading to data breaches, unauthorized access to critical resources, and privilege escalation. The scope of the impact depends on the permissions associated with the compromised Service Principal. If the Service Principal has high privileges, the attacker can gain control over the entire Azure AD tenant. Several threat actors, including APT29 and Scattered Lapsus$ Hunters, have been observed targeting Azure AD for persistence and privilege escalation.

## Recommendation

*   Deploy the Sigma rule provided to detect new credentials added to Service Principals by monitoring the `azure_monitor_aad` sourcetype and filtering for the "Update application*Certificates and secrets management" operation.
*   Investigate any detected instances of Service Principal credential modifications, especially if the user account performing the changes is not expected or has elevated privileges.
*   Implement multi-factor authentication (MFA) for all user accounts, including those with privileges to manage Service Principals.
*   Review and audit the permissions assigned to Service Principals to minimize the potential impact of a compromise.
*   Monitor and alert on suspicious sign-in activity associated with Service Principals, such as logins from unusual locations or at unusual times.
*   Regularly review the references provided for more information about Azure AD attack techniques and mitigation strategies.
