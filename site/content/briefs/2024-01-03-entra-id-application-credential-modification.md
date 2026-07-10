---
title: Entra ID Application Credential Modification
slug: 2024-01-03-entra-id-application-credential-modification
description: An adversary may add unauthorized credentials to an Azure application, enabling persistent access, evading defenses, and escalating privileges by modifying certificates or secrets.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - persistence
  - entra_id
  - account_manipulation
vendors:
  - Microsoft
products:
  - Azure
  - Entra ID
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
  - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/001/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: Entra ID Application Credential Modified
    description: Detects when a new credential is added to an application in Azure Active Directory (Entra ID), which can be a sign of malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - auditlogs
      - azure
  - title: Entra ID Application Credential Additions by Uncommon User
    description: Detects when an Entra ID application credential is created by a user that does not typically create them.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - auditlogs
      - azure
  - title: Entra ID Application Credential Additions to Privileged Application
    description: Detects when an Entra ID application credential is created on an application with high privileges.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - auditlogs
      - azure
rules_count: 3
---

This detection identifies when a new credential is added to an application in Azure. Azure applications use credentials like certificates or secret strings for identity verification during token requests. Adversaries may exploit this by adding unauthorized credentials, enabling persistent access or evading defenses. This tactic allows attackers to maintain access even if the original compromised account is remediated. The targeted applications are within the Entra ID environment. This activity is logged within the Azure audit logs and can be detected by monitoring for successful "Update application - Certificates and secrets management" operations.

## Attack Chain

1.  The attacker gains initial access to an account with permissions to modify Azure application registrations (e.g., via phishing or credential stuffing).
2.  The attacker identifies a target application registration within Entra ID.
3.  The attacker modifies the application registration to add a new certificate or secret string credential.
4.  The attacker uses the newly added credential to authenticate as the application.
5.  The attacker leverages the application's permissions to access resources within the Azure environment.
6.  The attacker may escalate privileges by granting the application additional roles or permissions.
7.  The attacker maintains persistent access to the Azure environment even if the initially compromised account is disabled.

## Impact

Successful exploitation allows attackers to maintain a persistent foothold within the Azure environment, even after the initial compromise is remediated. This can lead to data exfiltration, unauthorized access to resources, and further lateral movement within the cloud infrastructure. The severity depends on the application's permissions and the scope of the attacker's access, but could affect critical business functions if a high-privilege application is compromised.

## Recommendation

*   Deploy the Sigma rule "Entra ID Application Credential Modified" to detect unauthorized credential modifications within your Azure environment, ingesting `logs-azure.auditlogs-*` and `filebeat-*` indices.
*   Review Azure audit logs for the "Update application - Certificates and secrets management" operation name to identify potential malicious activity.
*   Implement stricter access controls and multi-factor authentication for accounts with permissions to manage Azure application registrations.
*   Monitor application access logs for unusual or unauthorized activity originating from application principals with newly added credentials.
*   Correlate application credential modifications with other suspicious activities, such as failed login attempts or privilege escalation events, to identify potential indicators of compromise.
