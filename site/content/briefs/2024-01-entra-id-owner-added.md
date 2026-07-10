---
title: Entra ID User Added as Registered Application Owner
slug: 2024-01-entra-id-owner-added
description: An adversary may add a user account as an owner for an Azure application in order to grant additional permissions and modify the application's configuration using another account, potentially leading to persistence, credential access, or privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - persistence
  - credential access
  - privilege escalation
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
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_user_added_as_owner_for_azure_application.toml
rules:
  - title: Entra ID User Added as Registered Application Owner
    description: Detects when a user is added as an owner for an Azure application, which can be indicative of malicious persistence or privilege escalation.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - auditlogs
      - azure
  - title: Entra ID Application Owner Added - High Privilege Account
    description: Detects when a user is added as an owner for an Azure application and the account added has elevated privileges.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - auditlogs
      - azure
rules_count: 2
---

Attackers may attempt to establish persistence, escalate privileges, or gain credential access within Azure environments by manipulating application ownership. This involves adding a malicious or compromised user account as an owner of an Azure application. By doing so, the attacker gains the ability to modify the application's configuration, grant additional permissions, and potentially access sensitive data associated with the application. This technique can be used to maintain unauthorized access to the environment even after other access methods have been revoked. This activity is logged within Azure audit logs, enabling detection through monitoring for specific operation names.

## Attack Chain

1. An attacker gains initial access to a compromised user account within the Azure environment.
2. The attacker identifies a target Azure application to which they want to add themselves or their controlled account as an owner.
3. Using the compromised account, the attacker attempts to add the new user account as an owner of the target application. This action generates an Azure audit log event.
4. The Azure Active Directory service processes the request to add the new owner to the application.
5. If the compromised account has sufficient privileges, the new user account is successfully added as an owner of the application.
6. The attacker logs in with the newly added owner account.
7. The attacker leverages the elevated privileges associated with the owner role to modify the application's configuration, grant additional permissions to other accounts, or access sensitive data.
8. The attacker maintains persistent access to the Azure environment through the compromised application.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, modification of application configurations, and persistence within the Azure environment. This could allow an attacker to maintain access to the environment even after the initial compromise is remediated. The number of affected applications and users depends on the scope of the attacker's access and the permissions associated with the compromised application. The original report assigns this a low risk score, but the impact can be significant depending on the compromised application's role.

## Recommendation

*   Deploy the Sigma rule "Entra ID User Added as Registered Application Owner" to your SIEM and tune for your environment to detect this specific activity in your Azure environment.
*   Review Azure audit logs for `azure.auditlogs.operation_name:"Add owner to application"` to identify potentially malicious additions of users as application owners.
*   Implement stricter approval processes for changes to application ownership and access control policies.
