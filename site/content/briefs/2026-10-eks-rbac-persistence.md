---
brief_id: brief-2026-10-21-eks-rbac-persistence
event_id: brief-2026-10-21-eks-rbac-persistence
revision: 1
activity_at: "2026-10-21T09:07:33Z"
title: 'AWS EKS: Creation or Modification of Sensitive RBAC Roles'
slug: 2026-10-eks-rbac-persistence
description: This detection identifies the creation or modification of Kubernetes Roles and ClusterRoles that include high-risk permissions, such as wildcard access or RBAC escalation verbs (bind, escalate, impersonate), which may facilitate privilege escalation or unauthorized access.
date: "2026-10-21T09:07:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - aws
  - eks
  - kubernetes
  - rbac
  - cloud
  - persistence
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.006
    subtechnique_name: Additional Container Cluster Roles
    evidence: Attackers commonly add a new ClusterRole with * verbs/resources and then use it to bind themselves or a service account to cluster-admin–equivalent access.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_sensitive_role_creation_or_modification_aws_eks.toml
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#overly-permissive-role-based-access-control
---

The creation or modification of Roles and ClusterRoles with high-risk RBAC permissions can silently expand privileges within an EKS cluster. Attackers may add a ClusterRole with wildcard (`*`) verbs or resources to bind themselves or service accounts to cluster-admin - equivalent access. Legitimate administrative or automated tasks may also trigger this activity; therefore, changes should be validated against expected operational workflows or version-controlled manifests.

## Recommendation
- Monitor EKS control-plane audit logs for the creation or modification of Roles and ClusterRoles.
- Investigate the identity and origin of changes, verifying if they originated from approved automation or interactive sessions.
- Compare Role/ClusterRole manifests before and after the change to identify the introduction of wildcard access or escalation verbs (bind, escalate, impersonate).
- Review associated RoleBindings or ClusterRoleBindings to determine which subjects gained effective permissions.
- Utilize RBAC guardrails (e.g., OPA Gatekeeper or Kyverno) to restrict wildcard or escalation verbs to approved groups.
