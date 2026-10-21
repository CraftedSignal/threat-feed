---
brief_id: brief-2026-10-21-eks-secrets-discovery
event_id: brief-2026-10-21-eks-secrets-discovery
revision: 1
activity_at: "2026-10-21T08:31:12Z"
title: 'AWS EKS: Kubernetes secret enumeration detection'
slug: 2026-10-eks-secrets-discovery
description: Detection of potential credential enumeration in AWS EKS via monitoring of control-plane audit logs for sensitive namespace or cluster-wide secret listing operations.
date: "2026-10-21T08:31:12Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - Amazon Elastic Kubernetes Service (EKS)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.007
    subtechnique_name: Container API
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_kubernetes_secrets_list_cluster_and_sensitive_namespaces_aws_eks.toml
---

Elastic has released a detection rule to identify 'list' operations on Kubernetes Secrets within AWS EKS clusters. The rule monitors for operations targeting '/api/v1/secrets' or namespaces such as 'kube-system' and 'default' when initiated from non-loopback IP addresses. This monitoring is intended to identify potential credential enumeration from remote clients. The implementation requires EKS control-plane audit logs to be enabled and ingested into the 'logs-aws.eks_audit-*' data stream.

## Recommendation
- Enable AWS EKS audit log streaming to the AWS integration.
- Deploy the detection logic to identify unauthorized service account or user access.
- Investigate findings by confirming the actor and reviewing the source IP, user agent, and follow-on API activity.
- If listing is unauthorized, revoke credentials, rotate exposed secrets, and tighten RBAC to ensure only required service accounts can list secrets in sensitive namespaces.
