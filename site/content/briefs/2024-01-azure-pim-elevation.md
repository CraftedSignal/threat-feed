---
title: Azure PIM Elevation Approved or Denied
slug: 2024-01-azure-pim-elevation
description: Detection of Azure Privileged Identity Management (PIM) elevation approvals or denials, which, if unexpected, may indicate unauthorized privilege escalation or malicious activity within an Azure environment.
date: "2024-01-03T18:27:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_activation_approve_deny.yml
rules:
  - title: Azure PIM Elevation Approved or Denied
    description: Detects when a PIM elevation is approved or denied.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Azure PIM Role Activation Request
    description: Detects when a PIM role activation is requested.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

The compromise of privileged accounts within cloud environments is a significant risk. Azure Privileged Identity Management (PIM) is designed to mitigate this risk by enforcing time-bound and approval-based role activation. This brief focuses on the detection of PIM elevation requests that are either approved or denied. While legitimate administrator actions will trigger these events, unexpected or unauthorized approvals/denials, especially those occurring outside of normal business hours or originating from unusual locations, warrant immediate investigation. This activity can indicate attempts at unauthorized privilege escalation, lateral movement, or data exfiltration within the Azure environment. Monitoring these events provides an opportunity to identify and respond to potential breaches before significant damage can occur.

## Attack Chain

1. An attacker gains initial access to a low-privileged Azure account, possibly through credential phishing or password reuse.
2. The attacker attempts to activate a privileged role (e.g., Global Administrator, Security Administrator) through Azure PIM.
3. The PIM request triggers an approval workflow, requiring authorization from designated approvers.
4. An attacker compromises an approver account, enabling them to approve their own malicious PIM request or deny a legitimate one.
5. Alternatively, an unwitting approver approves a malicious request, potentially due to social engineering.
6. Upon approval, the attacker's account is temporarily elevated to the requested privileged role.
7. The attacker leverages the elevated privileges to perform malicious actions, such as creating new accounts, modifying security policies, or accessing sensitive data.
8. The attacker attempts to maintain persistence by creating backdoor accounts or modifying access controls, potentially circumventing PIM restrictions.

## Impact

Successful exploitation can lead to full control over the Azure environment, potentially impacting hundreds or thousands of users and services. A compromised Global Administrator role grants the attacker the ability to access and modify all resources within the Azure tenant, leading to data breaches, service disruptions, and financial losses. The targeted sectors include any organization leveraging Azure PIM for privileged access management.

## Recommendation

*   Deploy the Sigma rule `Azure PIM Elevation Approved or Denied` to your SIEM to detect unusual PIM activity.
*   Investigate any PIM approval or denial events occurring outside of normal business hours or originating from unexpected locations, focusing on the `properties.message` field in the logs.
*   Implement multi-factor authentication (MFA) for all Azure accounts, especially those with approval permissions for PIM requests.
*   Regularly review and audit PIM role assignments and approval workflows to ensure they align with the principle of least privilege.
*   Enable alerting on changes to PIM policies and configurations to detect any unauthorized modifications.
*   Monitor Azure Audit Logs for suspicious activity following PIM role activation, looking for actions associated with common attack techniques (e.g., account creation, policy modification).
