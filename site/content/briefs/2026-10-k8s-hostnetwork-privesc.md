---
title: Kubernetes Pod Privilege Escalation via HostNetwork
slug: 2026-10-k8s-hostnetwork-privesc
description: Creation or modification of Kubernetes pods with the HostNetwork attribute enabled allows containers to escape their network namespace, potentially enabling host-level traffic interception and privilege escalation.
date: "2026-10-07T16:36:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - privilege-escalation
  - container-escape
vendors:
  - Kubernetes
products:
  - Kubernetes (all versions)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: The rule detects an attempt to create or modify a pod attached to the host network.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: Doing so gives the pod access to any service running on localhost of the host.
    confidence_band: high
references:
  - https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections
  - https://kubernetes.io/docs/concepts/security/pod-security-admission/
  - https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_hostnetwork.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy the detection query to Kubernetes audit log stream.
      owner: Detection Engineering
      due: 48h
      evidence: Required for visibility into pod creation events.
  mitigation_plan:
    - priority: immediate
      action: Implement Pod Security Admission (PSA) to restrict HostNetwork usage.
      owner: Infrastructure Team
      addresses: Prevention of unauthorized HostNetwork usage.
      evidence: Standard security practice for cluster hardening.
---

Kubernetes pods configured with the 'HostNetwork' attribute effectively share the node's network namespace, granting the container full access to the host's network interfaces. While this configuration is occasionally required for infrastructure components like ingress controllers or network plugins, it is a significant security risk when used by unauthorized or untrusted pods. Attackers who gain the ability to deploy or modify pods within a cluster can leverage this setting to snoop on host-level network traffic, communicate with services bound to the host's localhost, and bypass namespace-level network policies. This technique facilitates container escape scenarios and broader cluster compromise. Defenders should prioritize identifying and auditing pods that utilize 'HostNetwork', particularly those running outside of trusted system namespaces or using unverified container images.

## Impact

Successful exploitation allows an attacker to intercept inter-pod communication, access internal services not intended for the network, and potentially escalate privileges to the host node. This poses a high risk in multi-tenant environments where network isolation is a primary security boundary. Misconfiguration or abuse of this setting can lead to unauthorized data exfiltration and persistent monitoring of cluster internal traffic.

## Recommendation

- Deploy the provided Sigma-equivalent KQL rule to monitor Kubernetes audit logs for pod creations or modifications where 'hostNetwork' is set to 'true'.
- Conduct a regular audit of Kubernetes RBAC policies to ensure that only authorized service accounts possess the permissions required to create pods with privileged attributes.
- Establish a strict Pod Security Admission policy to prevent the deployment of pods with HostNetwork enabled by default.
- Review all existing pods currently utilizing 'HostNetwork' and document legitimate business requirements, ensuring that exceptions are explicitly defined and monitored.
- Integrate Kubernetes audit log monitoring into your SIEM, specifically focusing on 'create', 'patch', and 'update' events related to pod objects.
