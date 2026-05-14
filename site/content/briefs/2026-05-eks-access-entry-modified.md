---
title: AWS EKS Access Entry Modification Detected
slug: 2026-05-eks-access-entry-modified
description: Successful Amazon EKS Access Entries API operations that create, update, attach, detach, or delete authentication mappings between IAM principals and the cluster, potentially indicating persistence or privilege escalation are detected.
date: "2026-05-14T15:46:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - kubernetes
  - aws
  - persistence
  - privilege-escalation
vendors:
  - Amazon
products:
  - EKS
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
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_eks_access_entry_modified.toml
  - https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
rules:
  - title: AWS EKS Access Entry Modified
    description: Detects successful Amazon EKS Access Entries API operations that create, update, attach, detach, or delete authentication mappings between IAM principals and the cluster.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EKS Access Entry Modified - Uncommon ARN
    description: Detects successful Amazon EKS Access Entries API operations using uncommon ARN patterns.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies modifications to Amazon Elastic Kubernetes Service (EKS) access entries. Access entries define the authentication mappings between IAM principals and the Kubernetes cluster, controlling who can authenticate and their associated Kubernetes-level permissions. Attackers can abuse these access entries to establish persistence or escalate privileges within the cluster without directly modifying in-cluster RBAC objects. The rule specifically looks for `CreateAccessEntry`, `AssociateAccessPolicy`, `UpdateAccessEntry`, `DisassociateAccessPolicy`, and `DeleteAccessEntry` API calls. Common automation identities, such as service-linked roles, eksctl, Terraform, and CloudFormation role patterns, are excluded from triggering the alert to reduce false positives. This activity is important for defenders to monitor as it represents a potential bypass of traditional Kubernetes security controls.

## Attack Chain

1.  An attacker compromises an IAM principal with sufficient permissions to modify EKS access entries.
2.  The attacker uses the compromised IAM principal to call the `CreateAccessEntry` API to create a new access entry, mapping an attacker-controlled IAM principal to the EKS cluster.
3.  Alternatively, the attacker uses the `AssociateAccessPolicy` API to grant the attacker-controlled IAM principal elevated permissions within the EKS cluster by associating it with a policy such as `cluster-admin`.
4.  The attacker might use the `UpdateAccessEntry` API to modify an existing access entry, changing the associated IAM principal or Kubernetes groups.
5.  The attacker authenticates to the EKS cluster using the attacker-controlled IAM principal now associated with the access entry.
6.  The attacker performs privileged actions within the Kubernetes cluster based on the permissions granted through the access entry.
7.  The attacker maintains persistent access to the EKS cluster by ensuring the access entry remains active, even if other security measures are taken.

## Impact

Successful exploitation allows attackers to gain persistent and potentially privileged access to the EKS cluster. This can lead to data breaches, service disruption, or complete control over the cluster and its workloads. The damage depends on the level of permissions granted through the modified access entries. The number of affected clusters and the scope of the impact depends on the attacker's objectives and the overall security posture of the AWS environment.

## Recommendation

*   Deploy the provided Sigma rule "AWS EKS Access Entry Modified" to detect unauthorized modifications to EKS access entries within your environment. Tune the rule's exclusions based on your organization's legitimate automation patterns (`aws.cloudtrail.user_identity.arn` in the rule query).
*   Investigate any detected modifications to EKS access entries, focusing on the associated IAM principals and the Kubernetes-level permissions they receive (see "Investigation Guide" tag in the rule).
*   Review and restrict `eks:*` permissions to minimize the potential impact of compromised IAM principals (see rule description).
*   Correlate findings from this rule with the "EKS Access Entry Granted Cluster Admin Policy" rule to identify cases where cluster administrator privileges are granted through access entries.
