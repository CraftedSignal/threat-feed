---
brief_id: brief-2026-10-21-eks-hostnetwork-privilege-escalation
event_id: brief-2026-10-21-eks-hostnetwork-privilege-escalation
revision: 1
activity_at: "2026-10-21T14:00:15Z"
title: 'AWS EKS: Potential Privilege Escalation via HostNetwork Pod Creation'
slug: 2026-10-eks-hostnetwork-privilege-escalation
description: Kubernetes pods attached to the host network can access services running on the host's localhost, potentially allowing network traffic snooping or the bypassing of network policies.
date: "2026-10-21T14:00:15Z"
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
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
references:
  - https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections
  - https://kubernetes.io/docs/concepts/security/pod-security-policy/#host-namespaces
  - https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
  - rules/integrations/aws/privilege_escalation_pod_created_with_hostnetwork_aws_eks.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_pod_created_with_hostnetwork_aws_eks.toml
---

HostNetwork allows a pod to use the node network namespace. This access can be exploited to snoop on network activity of other pods on the same node or bypass restrictive network policies applied to its given namespace. The detection rule identifies pod creation or modification events with HostNetwork enabled, excluding known benign images.

## Triage and Analysis
- Review Kubernetes audit logs to identify the user or service account associated with the pod creation or modification.
- Examine the pod configuration, specifically container images, to determine if unauthorized images are being used.
- Assess the necessity of HostNetwork for the pod and determine if it can be reconfigured to operate without this setting.
- Check Kubernetes RBAC settings to ensure users/service accounts are not overly privileged.

## False Positives
- Administrative or developer pods running with host namespaces for debugging purposes.
- Monitoring, logging, or infrastructure services (e.g., CNI plugins, ingress controllers) that require HostNetwork for legitimate operations.
