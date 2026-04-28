---
title: Unauthorized Modification of Azure Conditional Access Policy
slug: 2024-05-29-azure-ca-policy-update
description: An unauthorized actor modifies an Azure Conditional Access policy, potentially leading to privilege escalation, credential access, persistence, or defense impairment.
date: "2024-05-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - conditional-access
  - policy-modification
  - attack.privilege-escalation
  - attack.credential-access
  - attack.persistence
  - attack.defense-impairment
  - attack.t1548
  - attack.t1556
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_ca_policy_updatedby_bad_actor.yml
rules:
  - title: CA Policy Updated by Non Approved Actor
    description: Detects modifications to Azure Conditional Access policies by potentially unauthorized actors.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1548
      - T1556
    data_sources:
      - azure
      - auditlogs
  - title: CA Policy Modified - MFA Bypass
    description: Detects modifications to Azure Conditional Access policies that may weaken MFA requirements.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1548
      - T1556
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

Compromised or malicious actors may attempt to modify Azure Conditional Access (CA) policies to weaken security controls, elevate privileges, or establish persistence within the Azure environment. Conditional Access policies are critical for enforcing organizational security standards, and unauthorized changes can have significant security implications. This activity is detected through Azure Audit Logs by monitoring for "Update conditional access policy" events. Defenders should investigate any modifications to Conditional Access policies to ensure they are legitimate and align with security best practices. Detecting and responding to unauthorized CA policy modifications is crucial for maintaining the integrity and security of the Azure environment.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access through compromised credentials or other means (not specified in source).
2.  **Privilege Escalation:** The attacker leverages existing privileges or exploits vulnerabilities to gain sufficient permissions to modify Conditional Access policies (e.g., through a compromised Global Administrator account).
3.  **Policy Enumeration:** The attacker enumerates existing Conditional Access policies to identify targets for modification using tools like Azure PowerShell or the Azure portal.
4.  **Policy Modification:** The attacker modifies a Conditional Access policy, for example, by weakening MFA requirements, excluding specific users or groups from the policy, or disabling the policy altogether.
5.  **Persistence:** By weakening or disabling Conditional Access policies, the attacker establishes a persistent foothold in the environment, allowing them to bypass security controls and maintain unauthorized access.
6.  **Credential Access:** With weakened MFA or other access controls, the attacker gains easier access to sensitive credentials.
7.  **Defense Impairment:** The modification of CA policies impairs the organization's defense mechanisms, making it easier for the attacker to perform malicious activities undetected.

## Impact

Successful modification of Conditional Access policies can lead to significant security breaches, including unauthorized access to sensitive data, privilege escalation, and persistent compromise of the Azure environment. The number of affected users and resources depends on the scope of the modified policies. Organizations may experience data loss, financial losses, and reputational damage.

## Recommendation

*   Deploy the "CA Policy Updated by Non Approved Actor" Sigma rule to your SIEM to detect unauthorized modifications to Conditional Access policies within your Azure environment.
*   Review the `properties.message` field in the Azure Audit Logs for "Update conditional access policy" events and compare "old" vs "new" values to understand the nature of the changes.
*   Implement strict role-based access control (RBAC) to limit the number of users who can modify Conditional Access policies.
*   Investigate any alerts generated by the Sigma rule and verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
*   Enable multi-factor authentication (MFA) for all users, especially those with administrative privileges, to reduce the risk of credential compromise (related to attack.credential-access tag).
