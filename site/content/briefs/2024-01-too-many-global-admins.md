---
title: Excessive Global Administrator Accounts in Azure PIM
slug: 2024-01-too-many-global-admins
description: Detection of an excessive number of Global Administrator accounts assigned within an Azure tenant, indicating potential privilege escalation or compromised accounts.
date: "2024-01-03T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - global_admin
  - privilege_escalation
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#there-are-too-many-global-administrators
rules:
  - title: Too Many Global Admins Assigned to Tenant
    description: Detects an event indicating too many global admins are assigned to the tenant.
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
  - title: Azure PIM - Global Admin Role Activated
    description: Detects activation of Global Admin role via Azure PIM
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
rules_count: 2
---

The presence of an excessive number of Global Administrator accounts in an Azure tenant poses a significant security risk. While the source does not attribute this activity to a specific threat actor, the risk event indicates a potential compromise of existing accounts, internal privilege abuse, or misconfiguration within the Azure environment. The alert triggers when the number of Global Administrator assignments exceeds a predefined threshold within Privileged Identity Management (PIM). Attackers may abuse highly privileged accounts to gain broad control over the Azure environment, deploy malicious workloads, exfiltrate data, or establish persistence.

## Attack Chain

1. **Initial Compromise:** An attacker compromises a low-privilege user account through phishing or credential stuffing.
2. **Privilege Escalation:** The attacker attempts to elevate privileges by exploiting misconfigured permissions or vulnerabilities within the Azure environment.
3. **Global Admin Role Assignment:** The attacker assigns the Global Administrator role to multiple accounts, including the compromised account, either directly or through PIM bypass.
4. **Lateral Movement:** With Global Administrator privileges, the attacker moves laterally within the Azure environment, accessing sensitive resources and data.
5. **Data Exfiltration:** The attacker exfiltrates sensitive data from cloud storage, databases, or virtual machines.
6. **Persistence:** The attacker establishes persistent access by creating backdoors, modifying access controls, or deploying rogue applications.
7. **Covering Tracks:** The attacker attempts to remove audit logs or disable security features to hide their activity.

## Impact

The compromise of Global Administrator accounts can lead to significant damage, including data breaches, financial loss, and reputational damage. Excessive admin accounts significantly widen the attack surface and increase the likelihood of successful attacks. The impact includes unauthorized access to sensitive data, disruption of business operations, and potential regulatory fines.

## Recommendation

*   Deploy the Sigma rule "Too Many Global Admins" to your SIEM and tune the threshold for your environment to detect excessive Global Administrator assignments in Azure PIM.
*   Review and reduce the number of Global Administrator accounts to the minimum necessary.
*   Implement multi-factor authentication (MFA) for all privileged accounts.
*   Monitor Azure audit logs for suspicious activity related to role assignments and privilege elevation.
*   Regularly review and update PIM policies to ensure appropriate access controls.
