---
title: Azure RBAC Privilege Escalation via Built-In Administrator Role Assignment
slug: 2026-08-azure-rbac-admin-assignment
description: Threat actors are observed abusing Azure Role-Based Access Control (RBAC) to gain unauthorized administrative privileges and achieve persistence by assigning high-privilege built-in roles to actor-controlled accounts.
date: "2026-08-27T05:27:52Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-0501
tags:
  - cloud-security
  - privilege-escalation
  - persistence
  - azure
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Threat actors can abuse Azure Role-Based Access Control (RBAC) by assigning high-privilege built-in administrator roles to accounts they control.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: These roles provide significant privileges and can be abused by attackers for ... persistence.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
rules:
  - title: Detect Azure RBAC Built-In Administrator Role Assignment
    description: Detects the assignment of high-privilege Azure built-in administrator roles which can indicate privilege escalation or persistence.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloud
      - azure
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for Azure RBAC assignments
      owner: Detection Engineering
      due: 24h
      evidence: High risk of privilege escalation via built-in roles
  hunt_leads:
    - lead: Search logs for all 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' actions over the last 30 days
      technique_id: T1098.003
      data_needed:
        - Azure Activity Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Recent cloud ransomware campaigns involve this TTP
  mitigation_plan:
    - priority: immediate
      action: Review and remove unnecessary high-privilege role assignments
      owner: Cloud Operations
      addresses: T1098.003
      evidence: Principle of least privilege
---

Recent cloud security investigations have highlighted the abuse of Azure Role-Based Access Control (RBAC) as a key mechanism for privilege escalation and persistence. Attackers, including identified threat actor Storm-0501, exploit the assignment of high-privilege built-in administrator roles to non-privileged accounts. By modifying role assignments via the Azure Portal, CLI, PowerShell, or API, adversaries ensure long-term, elevated access to cloud resources. The specific roles identified for abuse include Owner, Contributor, User Access Administrator, Azure File Sync Administrator, Reservations Administrator, and Role Based Access Control Administrator. This activity enables attackers to perform lateral movement, exfiltrate sensitive data, and disrupt cloud services. Defenders must monitor the 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' action within Azure Activity Logs to identify unauthorized modifications that deviate from standard administrative workflows.

## Attack Chain

1. The attacker gains initial access to a compromised account or service principal within the Azure tenant.
2. The attacker identifies an target account or identity under their control to elevate.
3. The attacker issues a request to modify RBAC roles using the Azure API, CLI, or PowerShell.
4. The request triggers the 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' operation in the Azure Activity Log.
5. The system processes the assignment of a high-privilege role, such as 'Owner' or 'User Access Administrator', to the attacker-controlled identity.
6. The attacker leverages the new administrative permissions to access sensitive cloud assets or perform further configuration changes.
7. The attacker maintains long-term access (persistence) by ensuring the elevated role remains assigned.

## Impact

Successful abuse of these roles grants attackers comprehensive control over Azure subscriptions and resource groups. This impact includes the potential for total loss of confidentiality, integrity, and availability for affected cloud environments. Observed targeting suggests that attackers use these techniques to facilitate cloud-based ransomware operations and unauthorized resource manipulation.

## Recommendation

Prioritize the detection of unauthorized role assignments by deploying activity log monitoring.
- Enable and ingest Azure Activity Logs (Microsoft.Authorization/roleAssignments/write) into the SIEM.
- Deploy the provided Sigma rule to alert on the assignment of high-privilege built-in administrator roles.
- Conduct a historical audit of role assignments to identify recent elevation patterns for service principals and user accounts.
- Implement Privileged Identity Management (PIM) and Just-In-Time (JIT) access policies to restrict permanent administrative assignments.
- Enforce Multi-Factor Authentication (MFA) for all administrative and high-privilege service principal operations.
