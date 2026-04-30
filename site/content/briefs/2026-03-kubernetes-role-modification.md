---
title: Kubernetes Sensitive Role Creation or Modification
slug: 2026-03-kubernetes-role-modification
description: This rule detects the creation or modification of Kubernetes Roles or ClusterRoles that grant high-risk permissions, such as wildcard access or RBAC escalation verbs (e.g., bind, escalate, impersonate), potentially leading to privilege escalation or unauthorized access within the cluster.
date: "2026-03-05T13:13:30Z"
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

This detection rule, sourced from Elastic's detection-rules repository, focuses on identifying malicious activity within Kubernetes environments. Specifically, it targets the creation, update, or patching of Roles and ClusterRoles that introduce high-risk RBAC permissions. These permissions include wildcard access (e.g., `*`) and escalation verbs such as `bind`, `escalate`, or `impersonate`. The rule leverages audit logs to monitor these actions and flags those that could lead to privilege escalation or unauthorized access. The rule aims to detect attackers attempting to add a new ClusterRole with `*` verbs/resources and then using it to bind themselves or a service account to cluster-admin–equivalent access. This is important because attackers can silently expand privileges and enable persistence or lateral movement across the cluster.

## Attack Chain

1.  An attacker gains initial access to a Kubernetes cluster, possibly through compromised credentials or a vulnerable application.
2.  The attacker attempts to create a new ClusterRole or Role with broad permissions, including wildcard verbs and resources.
3.  The attacker may use `kubectl` or a similar tool to apply a YAML manifest defining the malicious role.
4.  The Kubernetes API server receives the request to create the role, and the audit logging system captures the event.
5.  The attacker then attempts to bind the newly created role to a service account or user, granting them the elevated permissions. This is achieved by creating or modifying a RoleBinding or ClusterRoleBinding object.
6.  The Kubernetes API server logs the creation or modification of the RoleBinding or ClusterRoleBinding.
7.  With the elevated permissions, the attacker can now perform actions they were previously unauthorized to do, such as accessing sensitive data, deploying malicious containers, or modifying cluster configurations.
8.  The attacker leverages these elevated privileges to establish persistence within the cluster and potentially move laterally to other resources or environments.

## Impact

A successful attack can lead to full cluster compromise, allowing the attacker to control all resources and data within the Kubernetes environment. This can result in data breaches, service disruptions, and significant financial losses. The severity depends on the scope of the compromised role and the resources it grants access to. Even seemingly minor modifications can have a cascading effect, enabling attackers to gain complete control over critical systems.

## Recommendation

*   Deploy the Sigma rule "Kubernetes Creation or Modification of Sensitive Role" to your SIEM and tune it for your environment to detect suspicious RBAC changes (rule.name).
*   Monitor Kubernetes audit logs for the creation or modification of Roles and ClusterRoles with wildcard permissions or escalation verbs (kubernetes.audit.requestObject.rules.verbs, kubernetes.audit.requestObject.rules.resources).
*   Implement RBAC guardrails, such as OPA Gatekeeper or Kyverno policies, to prevent the creation of overly permissive roles (references).
*   Restrict who can create or update RBAC objects and require all RBAC changes to go through code review and signed GitOps automation (references).
*   Regularly review existing Roles and ClusterRoles to identify and remove any unnecessary or overly broad permissions.
*   Enable Sysmon process creation logging on nodes to enhance detection capabilities around kubectl usage.
