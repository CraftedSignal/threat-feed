---
title: Kubernetes Sensitive RBAC Change Followed by Workload Modification
slug: 2026-09-kubernetes-rbac-workload
description: Adversaries escalate privileges in Kubernetes by modifying Roles or ClusterRoles to grant high-risk permissions, followed by the deployment or patching of workloads to establish persistence and execute malicious containers.
date: "2026-09-01T17:53:41Z"
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
  - cloud
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This rule detects when a user grants or broadens high-risk permissions in a Role/ClusterRole and then quickly creates or patches a DaemonSet, Deployment, or CronJob.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Attackers often add wildcard access or escalation verbs to a new role, bind it to their identity, then patch a workload to run a malicious container across nodes or on a schedule to establish persistence.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_sensitive_rbac_change_followed_by_workload_modification.toml
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#overly-permissive-role-based-access-control
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the EQL-based detection rule to the SIEM environment for Kubernetes audit logs
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific EQL rule for detecting this sequence.
  mitigation_plan:
    - priority: immediate
      action: Restrict modifications to RBAC resources to approved service accounts and require peer review for production cluster changes
      owner: DevOps
      addresses: T1098.006
      evidence: Source recommends hardening by enforcing least-privilege RBAC and requiring peer approval.
---

This threat involves a multi-stage attack pattern where an attacker leverages Kubernetes API server vulnerabilities or compromised credentials to gain unauthorized access. The attacker first creates or updates a Role or ClusterRole to include high-risk permissions, such as wildcard resource access, impersonation, or escalation verbs. Shortly after, the attacker creates or patches a sensitive workload resource - specifically a DaemonSet, Deployment, or CronJob. By binding these elevated permissions to their identity or a service account, the attacker can deploy malicious containers that execute across the cluster, establish persistence via CronJobs, or access sensitive environment secrets. This technique is often observed as a sequence, with the workload modification occurring within a short window (typically minutes) of the RBAC adjustment, effectively enabling the attacker to weaponize their new privileges to run payloads in the cluster environment.

## Attack Chain

1. Attacker gains authenticated access to the Kubernetes API server using compromised service account tokens or user credentials.
2. Attacker queries existing roles or identifies a target namespace to modify security configurations.
3. Attacker issues a POST or PATCH request to the API server to update a Role or ClusterRole with broad, high-risk permissions (e.g., wildcard access or 'escalate'/'bind' verbs).
4. Attacker optionally performs a RoleBinding or ClusterRoleBinding update to associate the modified role with their current identity.
5. Attacker identifies a target workload (DaemonSet, Deployment, or CronJob) that can be leveraged for persistence or execution.
6. Attacker issues a POST or PATCH request to modify the workload specification, adding malicious container images, hostPath mounts, or elevated security contexts.
7. Kubernetes controller reconciles the changes, causing the malicious workload to pull an attacker-controlled image and execute in the cluster.
8. Attacker uses the running workload to exfiltrate secrets, initiate outbound C2 connections, or maintain long-term persistence.

## Impact

Successful exploitation allows for full cluster compromise, unauthorized access to sensitive service tokens and secrets, and the deployment of persistent malicious workloads across nodes. This can lead to massive data exfiltration, lateral movement into cloud environments, and potential disruption of critical business services running within the Kubernetes cluster.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Deploy the provided EQL rule to monitor Kubernetes API audit logs for suspicious sequences of RBAC changes followed by workload modifications.
- Establish a baseline for all GitOps-based service accounts (e.g., flux-system) and exclude them from detection logic to reduce false positives.
- Enforce least-privilege RBAC policies and require peer approval for any modifications to Roles or ClusterRoles.
- Implement admission controllers to prevent the creation of privileged pods, pods with hostPath mounts, or images sourced from unapproved registries.
- Enable robust logging for the Kubernetes API server audit log and stream these events into the SIEM for real-time correlation.
