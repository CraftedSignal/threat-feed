---
title: Azure AD Device Registration Policy Changes Detected
slug: 2024-01-device-registration-policy-change
description: Monitoring changes to the device registration policy can detect potential privilege escalation or defense impairment attempts by malicious actors aiming to weaken security controls related to device management in Azure Active Directory.
date: "2024-01-26T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - device-registration
  - policy-change
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#device-registrations-and-joins-outside-policy
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_device_registration_policy_changes.yml
rules:
  - title: Azure AD Device Registration Policy Modified
    description: Detects modifications to the Azure AD device registration policy.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - privilege-escalation
    techniques:
      - T1484
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD Device Registration Policy Modified by Unusual User
    description: Detects modifications to the Azure AD device registration policy made by a user who rarely performs this action.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - privilege-escalation
    techniques:
      - T1484
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

The device registration policy in Azure Active Directory controls which devices can be registered or joined to the Azure AD tenant. Modification of this policy can weaken security controls, allowing unauthorized devices to access corporate resources. This activity is often associated with threat actors attempting to escalate privileges or impair existing defenses. This brief focuses on detecting changes to the Azure AD device registration policies using Azure Audit Logs, providing detection engineers with the ability to monitor and alert on potentially malicious modifications to this critical security control.

## Attack Chain

1.  The attacker compromises an account with sufficient privileges to modify Azure AD policies, such as a Global Administrator or Privileged Role Administrator.
2.  The attacker authenticates to the Azure portal or uses Azure PowerShell/CLI to interact with Azure AD.
3.  The attacker modifies the device registration policy, potentially allowing non-compliant devices to register or join the domain. This may involve changing settings related to multi-factor authentication, device compliance, or allowed operating systems.
4.  The Azure AD Audit Logs record an event with ActivityDisplayName equal to 'Set device registration policies' under the 'Policy' Category.
5.  The attacker registers a rogue device that does not meet the organization's security standards.
6.  The rogue device gains access to sensitive corporate resources, bypassing intended security controls.
7.  The attacker uses the rogue device to perform further malicious activities, such as data exfiltration or lateral movement.

## Impact

Successful modification of the device registration policy can lead to unauthorized devices accessing sensitive corporate resources, bypassing multi-factor authentication or device compliance requirements. This can result in data breaches, privilege escalation, and further compromise of the Azure AD environment. The impact can be severe if the attacker leverages the policy change to register multiple rogue devices, creating a persistent backdoor into the organization's resources.

## Recommendation

*   Deploy the Sigma rule "Changes to Device Registration Policy" to your SIEM and tune for your environment to detect unauthorized modifications to device registration policies (rule).
*   Review Azure AD audit logs for any unexpected "Set device registration policies" events (logsource).
*   Implement multi-factor authentication for all administrative accounts to prevent unauthorized policy changes (TTP).
