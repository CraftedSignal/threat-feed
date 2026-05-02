---
title: Kubernetes Sensitive Role Creation or Modification
slug: 2024-01-kubernetes-sensitive-role-creation
description: Detects the creation or modification of Kubernetes Roles or ClusterRoles that grant high-risk permissions, such as wildcard access or RBAC escalation verbs, potentially leading to privilege escalation or unauthorized access within the cluster.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - rbac
  - privilege-escalation
  - persistence
products:
  - Kubernetes
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
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#overly-permissive-role-based-access-control
rules:
  - title: Kubernetes Creation of Sensitive Role
    description: Detects the creation of Kubernetes Roles or ClusterRoles that grant high-risk permissions, such as wildcard access or RBAC escalation verbs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Role Modification with Escalation Verbs
    description: Detects modifications to Kubernetes Roles or ClusterRoles that introduce escalation verbs like bind, escalate, or impersonate.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection rule focuses on identifying suspicious activities related to Kubernetes Role-Based Access Control (RBAC). It specifically targets the creation, update, or patching of Kubernetes Roles or ClusterRoles that introduce high-risk permissions. These include wildcard access, where a single rule grants access to all resources, and escalation verbs like 'bind', 'escalate', or 'impersonate', which can be used to elevate privileges. The rule is designed to alert security teams to potential privilege escalation or unauthorized access attempts within Kubernetes environments. The Elastic detection rule was last updated on April 27, 2026, and aims to detect malicious actors attempting to gain cluster-admin-equivalent access by creating new ClusterRoles with `*` verbs/resources and binding them to their accounts or service accounts.

## Attack Chain

1.  An attacker gains initial access to the Kubernetes cluster, potentially through compromised credentials or a vulnerable application.
2.  The attacker attempts to create or modify a Role or ClusterRole.
3.  The attacker adds high-risk permissions to the Role or ClusterRole, such as wildcard verbs/resources (`*`) or escalation verbs (bind, escalate, impersonate).
4.  The Kubernetes API server authorizes the request, potentially due to misconfigured RBAC policies.
5.  The attacker creates or modifies a RoleBinding or ClusterRoleBinding to associate the modified Role or ClusterRole with a target user, group, or service account.
6.  The target user, group, or service account now possesses the elevated privileges granted by the modified Role or ClusterRole.
7.  The attacker leverages the elevated privileges to perform unauthorized actions within the cluster, such as accessing sensitive data or deploying malicious workloads.
8.  The attacker achieves persistence by maintaining the modified Role or ClusterRole and its associated bindings, allowing continued access to elevated privileges.

## Impact

Successful exploitation can lead to significant security breaches within a Kubernetes environment. Attackers can gain unauthorized access to sensitive data, deploy malicious workloads, disrupt services, and potentially compromise the entire cluster. This can result in data breaches, financial losses, and reputational damage. The rule aims to prevent attackers from silently expanding privileges, enabling persistence, or facilitating lateral movement across the cluster.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Creation of Sensitive Role` to your SIEM to detect the creation or modification of Kubernetes Roles or ClusterRoles that grant high-risk permissions.
*   Enable Kubernetes audit logging to capture the necessary events for the Sigma rules to function effectively (reference: Kubernetes audit logs in `logsource`).
*   Implement RBAC guardrails using tools like OPA Gatekeeper or Kyverno to prevent the creation of Roles/ClusterRoles with wildcard or escalation verbs (reference: harden recommendation in the content).
*   Regularly review and audit RBAC configurations to identify and remediate overly permissive roles and bindings.
