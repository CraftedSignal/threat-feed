---
title: Entra ID User Added as Service Principal Owner for Persistence
slug: 2024-01-entra-id-sp-owner-added
description: An adversary may add a user account as an owner for an Azure service principal to define what an application can do in the Azure AD tenant, potentially leading to persistence and privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - service-principal
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Entra ID
  - Azure
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals
rules:
  - title: Entra ID User Added as Service Principal Owner
    description: Detects when a user is added as an owner to an Azure service principal, which can be used for persistence and privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1098
    data_sources:
      - audit
      - azure
  - title: Entra ID Service Principal Owner Add Failed
    description: Detects failed attempts to add a user as an owner of an Azure service principal.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1098
    data_sources:
      - audit
      - azure
rules_count: 2
---

This alert identifies when a user is added as an owner for an Azure service principal. Service principals define what an application can do within a tenant, who can access it, and what resources it can access. Attackers might add a user account as an owner to a service principal. This allows them to manipulate the application's permissions within the Azure AD tenant. This can lead to attackers gaining unauthorized access, persistence, and privilege escalation within the Azure environment. The rule specifically looks for "Add owner to service principal" events in Azure audit logs. The alert can be triggered by routine administrative changes, automated processes, organizational changes, and third-party applications.

## Attack Chain

1. An attacker gains initial access to an Azure account with sufficient privileges.
2. The attacker enumerates existing Azure service principals within the tenant.
3. The attacker selects a service principal to target.
4. The attacker adds a malicious user account as an owner of the targeted service principal using the Azure portal or command-line tools.
5. The attacker leverages the newly gained ownership to modify the service principal's permissions, granting the attacker's account elevated privileges.
6. The attacker uses the service principal to access resources and data within the Azure environment that were previously inaccessible.
7. The attacker establishes persistence by maintaining control over the service principal, even if their initial access is revoked.

## Impact

Successful exploitation allows an attacker to achieve persistence and escalate privileges within the Azure environment. This could lead to unauthorized access to sensitive data, disruption of services, and potential compromise of the entire Azure tenant. While the number of affected organizations isn't specified, the severity of a successful attack could be substantial, especially in organizations heavily reliant on Azure services.

## Recommendation

*   Deploy the Sigma rule "Entra ID User Added as Service Principal Owner" to your SIEM to detect this activity in real-time and tune for your environment.
*   Review the audit log entry to confirm the event dataset is 'azure.auditlogs' and the operation name is "Add owner to service principal" with a successful outcome as described in the rule description.
*   Implement conditional access policies to restrict who can add owners to service principals as described in the rule's "Response and remediation" section.
*   Create exceptions for known administrative accounts that frequently perform these actions, as described in the "False positive analysis" section.
