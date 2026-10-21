---
brief_id: brief-2026-10-21-eks-credential-access
event_id: brief-2026-10-21-eks-credential-access
revision: 1
activity_at: "2026-10-21T07:46:50Z"
title: 'AWS EKS: Potential Unauthorized Kubernetes Secret access'
slug: 2026-10-eks-credential-access
description: Kubernetes audit identities for kubelet (system:node:*) and workloads (system:serviceaccount:*) performing 'get' or 'list' operations on Secret objects may indicate credential access, as attackers use these methods to sweep for tokens, registry credentials, TLS keys, or application configuration.
date: "2026-10-21T07:46:50Z"
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
  - cloud
  - kubernetes
  - aws
  - credential-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.007
    subtechnique_name: Container API
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens
  - rules/integrations/aws/credential_access_kubernetes_secret_read_by_node_or_pod_service_account_aws_eks.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_kubernetes_secret_read_by_node_or_pod_service_account_aws_eks.toml
---

Kubernetes audit identities (system:node:* and system:serviceaccount:*) are intended to operate with predictable API usage. Direct 'get' or 'list' operations on the Secrets API by these principals can be a sign of credential access, as compromised tokens or node credentials may be used to exfiltrate sensitive material.

## Investigation Guidance
- Review RBAC RoleBindings and ClusterRoleBindings for the identified node or workload.
- Inspect the namespace, object name, source IP, and user agent to differentiate between recognized automation and anomalous activity.
- Review authorization decisions in the audit logs to distinguish successful reads from probing denials.
- Correlate activity with other events such as pod execs, token creation, or RoleBinding modifications.

## False Positives
- In-cluster operators, CSI drivers, GitOps agents, and platform controllers may legitimately interact with Secrets.
- Rare kubelet or node maintenance tooling may access Secret APIs.
