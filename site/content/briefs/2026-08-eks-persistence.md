---
title: Abuse of Amazon EKS Access Entries for Persistent Backdoor Establishment
slug: 2026-08-eks-persistence
description: Adversaries with EKS administrative permissions may exploit EKS access entries to temporarily grant themselves cluster-admin access, establish persistent Kubernetes RBAC backdoors, and delete the access entry to conceal their activity.
date: "2026-08-26T13:55:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - kubernetes
  - persistence
vendors:
  - Amazon
products:
  - Elastic Kubernetes Service
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary with EKS administrative access may temporarily grant themselves cluster access, use those permissions to create Kubernetes RBAC resources, and then delete the access entry to hide the evidence.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateAccessEntry.html
  - https://docs.aws.amazon.com/eks/latest/APIReference/API_DeleteAccessEntry.html
  - https://www.wiz.io/blog/new-attack-vectors-emerge-via-recent-eks-access-entries-and-pod-identity-features
  - https://securitylabs.datadoghq.com/articles/eks-cluster-access-management-deep-dive/
rules:
  - title: Detect AWS EKS Access Entry Created Then Deleted by Same Identity
    description: Detects the creation of an Amazon EKS access entry followed by its deletion by the same identity within a 5-minute window, indicative of potential backdoor installation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.006
    data_sources:
      - process_creation
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for short-window EKS access entry creation/deletion
      owner: Detection Engineering
      due: 48h
      evidence: Source provides EQL logic for event correlation
  mitigation_plan:
    - priority: immediate
      action: Restrict EKS administrative IAM permissions
      owner: IT Operations
      addresses: T1098.006
      evidence: Source recommends applying IAM policies restricting Create/DeleteAccessEntry to specific roles
---

Adversaries possessing sufficient AWS IAM permissions (`eks:CreateAccessEntry` and `eks:DeleteAccessEntry`) are leveraging Amazon EKS access entries to establish long-term persistence in Kubernetes clusters. By creating an access entry linked to their own IAM principal with high-privilege cluster-admin permissions, attackers can interact directly with the Kubernetes API to deploy backdoors, such as privileged `ServiceAccounts`, `ClusterRoleBindings`, or unauthorized `DaemonSets`. Once these persistent RBAC objects are established, the attacker deletes the EKS access entry to remove the CloudTrail audit trail associated with the initial grant. This technique effectively hides the method of entry while maintaining unauthorized control over the cluster through legitimate-looking Kubernetes-level resources. Defenders must monitor for short-duration grant-and-revoke cycles of EKS access entries, as this behavioral pattern is highly characteristic of this persistence strategy.

## Attack Chain

1. Attacker gains AWS credentials with `eks:CreateAccessEntry` and `eks:DeleteAccessEntry` permissions.
2. Attacker calls `CreateAccessEntry` via the EKS API to map their IAM principal to a cluster-admin Kubernetes group.
3. Attacker connects to the target EKS cluster using the newly provisioned access.
4. Attacker performs a `create` operation on Kubernetes resources (e.g., `ClusterRoleBindings` or `ServiceAccounts`) to create a persistent backdoor.
5. Attacker executes further malicious commands, such as deploying rogue `DaemonSets` or accessing sensitive secrets within the cluster.
6. Attacker calls `DeleteAccessEntry` via the EKS API to remove the association between their IAM principal and the cluster.
7. The EKS access entry is removed, leaving behind the persistent Kubernetes-level backdoor while clearing the primary CloudTrail evidence of access.

## Impact

Successful exploitation allows for long-term, stealthy administrative access to EKS-based Kubernetes clusters. Unauthorized access can lead to container escape, exfiltration of sensitive secrets stored in the cluster, and manipulation of workloads. The number of impacted organizations depends on the strength of IAM controls and the visibility into Kubernetes audit logs, which are often siloed from traditional cloud management logs.

## Recommendation

- Implement monitoring for the EKS access entry grant-and-revoke cycle using the provided detection logic.
- Review Kubernetes audit logs for `create` events involving `ClusterRoleBindings`, `RoleBindings`, `ServiceAccounts`, or `DaemonSets` that coincide with suspicious EKS access entry creation.
- Audit existing Kubernetes RBAC configurations for unauthorized high-privilege service accounts or bindings.
- Restrict `eks:CreateAccessEntry` and `eks:DeleteAccessEntry` IAM permissions to only the most trusted administrative identities or automated CI/CD roles.
