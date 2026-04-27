---
title: Kubernetes Sensitive Role Creation or Modification
slug: 2026-03-kubernetes-role-modification
description: This rule detects the creation or modification of Kubernetes Roles or ClusterRoles that grant high-risk permissions, such as wildcard access or RBAC escalation verbs (e.g., bind, escalate, impersonate), potentially leading to privilege escalation or unauthorized access within the cluster.
date: "2026-03-05T13:13:30Z"
severities:
  - medium
tags:
  - kubernetes
  - rbac
  - privilege-escalation
  - persistence
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
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/006/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Kubernetes Role/ClusterRole Creation with Wildcard Permissions
    description: Detects the creation of Kubernetes Roles or ClusterRoles with wildcard permissions (*), which can lead to privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - auditd
      - kubernetes
  - title: Kubernetes Role/ClusterRole Modification to Include Escalation Verbs
    description: Detects modifications (update, patch) to Kubernetes Roles or ClusterRoles that introduce escalation verbs (bind, escalate, impersonate).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

This detection rule, sourced from Elastic's detection-rules repository, focuses on identifying malicious activity within Kubernetes environments. Specifically, it targets the creation, update, or patching of Roles and ClusterRoles that introduce high-risk RBAC permissions. These permissions include wildcard access (e.g., `*`) and escalation verbs such as `bind`, `escalate`, or `impersonate`. The rule leverages audit logs to monitor these actions and flags those that could lead to privilege…
