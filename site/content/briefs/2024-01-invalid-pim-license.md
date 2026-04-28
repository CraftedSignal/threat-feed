---
title: Azure Privileged Identity Management (PIM) Invalid License Detection
slug: 2024-01-invalid-pim-license
description: Detection of unauthorized access or privilege escalation attempts within Azure environments due to invalid or missing Microsoft Entra Premium P2 or Microsoft Entra ID Governance licenses for Privileged Identity Management (PIM).
date: "2024-01-22T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - privileged-identity-management
  - invalid-license
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#the-organization-doesnt-have-microsoft-entra-premium-p2-or-microsoft-entra-id-governance
rules:
  - title: Azure PIM - Invalid License Alert
    description: Detects events indicating an invalid Microsoft Entra Premium P2 or Microsoft Entra ID Governance license for Privileged Identity Management (PIM).
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
  - title: Azure PIM - Expired License Alert
    description: Detects events indicating an expired Microsoft Entra Premium P2 or Microsoft Entra ID Governance license for Privileged Identity Management (PIM).
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
rules_count: 2
---

This alert identifies scenarios where an organization lacks the necessary Microsoft Entra Premium P2 or Microsoft Entra ID Governance licenses required for proper Privileged Identity Management (PIM) functionality. Attackers may attempt to exploit misconfigured or unlicensed PIM deployments to gain unauthorized privileged access to critical Azure resources. This detection is crucial as it indicates a compliance issue that can be leveraged to escalate privileges, bypass security controls, and potentially lead to data breaches or system compromise. The absence of appropriate licensing hinders the effectiveness of PIM controls, creating opportunities for malicious actors to operate undetected. Defenders need to ensure appropriate licenses are in place.

## Attack Chain

1.  The attacker identifies an Azure environment lacking a valid Microsoft Entra Premium P2 or Microsoft Entra ID Governance license for Privileged Identity Management (PIM).
2.  The attacker attempts to activate a privileged role within the Azure environment through PIM.
3.  Due to the invalid license, the PIM activation process may not enforce proper multi-factor authentication (MFA) or approval workflows.
4.  The attacker gains unauthorized access to the privileged role without proper authorization or auditing.
5.  The attacker leverages the compromised privileged role to access sensitive Azure resources, such as virtual machines, databases, or storage accounts.
6.  The attacker performs malicious actions, such as data exfiltration, modification of system configurations, or deployment of malware.
7.  The attacker attempts to establish persistence within the Azure environment by creating rogue user accounts or modifying existing access controls.

## Impact

The impact of an invalid PIM license can be severe. Organizations may experience unauthorized access to critical Azure resources, leading to data breaches, system compromise, and compliance violations. The absence of proper PIM controls can enable attackers to escalate privileges, bypass security measures, and operate undetected within the Azure environment. Identifying invalid PIM licenses is crucial for maintaining the security and integrity of Azure deployments.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `invalidLicenseAlertIncident` events in Azure PIM logs (logsource: azure, service: pim).
*   Investigate any detected instances of `invalidLicenseAlertIncident` to determine the scope of the issue and potential unauthorized access.
*   Verify that all Azure subscriptions utilizing PIM have valid Microsoft Entra Premium P2 or Microsoft Entra ID Governance licenses.
*   Implement automated monitoring to proactively identify and alert on invalid PIM licenses.
