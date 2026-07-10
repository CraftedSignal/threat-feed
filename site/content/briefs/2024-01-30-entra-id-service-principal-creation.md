---
title: Entra ID Service Principal Creation for Persistence
slug: 2024-01-30-entra-id-service-principal-creation
description: An adversary may create a new service principal in Microsoft Entra ID to establish persistence and potentially impersonate legitimate services or applications, blending in with normal activity.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - entra_id
  - service_principal
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft Azure
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
  - https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal
rules:
  - title: Entra ID Service Principal Created
    description: Detects the creation of new service principals in Microsoft Entra ID, which could be used for persistence or lateral movement.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - audit
      - azure
  - title: Entra ID Service Principal Creation - High Privileges
    description: Detects the creation of service principals with highly privileged roles in Microsoft Entra ID.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136.003
    data_sources:
      - audit
      - azure
rules_count: 2
---

This rule detects the creation of new service principals within Microsoft Entra ID. Service principals are identities used by applications, services, and automation tools to access specific resources within Azure. While legitimate use of service principals is common for automation and application access, adversaries can create them to establish persistence mechanisms or to masquerade as legitimate services or applications. This activity is often performed to maintain unauthorized access to cloud resources and evade detection by blending in with normal automated processes. Identifying anomalous service principal creation can help prevent malicious actors from maintaining a foothold within an Azure environment. The rule focuses on detecting the "Add service principal" operation within the Azure Audit Logs.

## Attack Chain

1. An attacker gains initial access to an Azure environment through compromised credentials or a vulnerability.
2. The attacker authenticates to the Azure portal or uses the Azure CLI/PowerShell with the compromised account.
3. The attacker executes commands to create a new service principal within the Entra ID tenant. This involves assigning a name, application ID, and defining the roles and permissions for the service principal.
4. The service principal is configured with specific roles, granting it access to various Azure resources.
5. The attacker uses the newly created service principal to authenticate and access Azure resources.
6. The attacker leverages the service principal's permissions to perform malicious activities, such as data exfiltration, resource modification, or lateral movement.
7. The attacker uses the service principal for long-term persistence, maintaining access even if the initial access vector is remediated.

## Impact

Successful exploitation allows attackers to maintain persistent access to Azure resources. Depending on the assigned roles and permissions, the attacker can perform a wide range of malicious activities, including data exfiltration, resource manipulation, and further compromise of the environment. The impact is limited to the permissions granted to the created service principal but can be significant if the service principal is assigned highly privileged roles. Since this is an Entra ID event, all organizations utilizing Azure services are potentially in scope.

## Recommendation

*   Deploy the Sigma rule "Entra ID Service Principal Created" to your SIEM and tune for your environment, focusing on excluding known good service principal creation activities (e.g., from automated deployment pipelines).
*   Review and audit existing service principals and their assigned roles regularly to identify any suspicious or unauthorized principals.
*   Monitor Azure Audit Logs for unusual or unauthorized "Add service principal" operations, paying close attention to the identity creating the service principal.
*   Follow Microsoft's security best practices for identity management in Azure ([https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices)).
