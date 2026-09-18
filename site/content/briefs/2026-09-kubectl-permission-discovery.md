---
title: Kubernetes Permission Discovery via Kubectl
slug: 2026-09-kubectl-permission-discovery
description: Adversaries utilize the 'kubectl auth can-i' command to enumerate effective permissions and identify security misconfigurations within Kubernetes clusters, facilitating unauthorized access and privilege escalation.
date: "2026-09-18T19:13:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - kubernetes
  - container
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: Adversaries may use this command to enumerate permissions and discover potential misconfigurations in the cluster.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: The rule detects the use of the kubectl auth can-i command, which is used to check permissions in Kubernetes clusters.
    confidence_band: high
references:
  - https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/discovery_kubectl_permission_discovery.toml
rules:
  - title: Detect Kubectl Permission Discovery
    description: Detects the use of the kubectl auth can-i command, which is often used by adversaries to enumerate cluster permissions and discover potential misconfigurations.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security
  immediate_actions:
    - action: Deploy Sigma detection rule to SOC pipeline
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  mitigation_plan:
    - priority: medium_term
      action: Review Kubernetes RBAC roles and implement least privilege
      owner: Cloud Security
      addresses: T1069
      evidence: Source recommendations on remediation
---

The command 'kubectl auth can-i' is a native Kubernetes utility designed to allow administrators and developers to verify their access rights against the Kubernetes API. While legitimate, this command is frequently leveraged by threat actors to perform reconnaissance once an initial foothold within a container or cluster-connected host is achieved. By systematically probing the API, an attacker can determine the extent of their current privileges, identify over-privileged service accounts, and pinpoint paths for lateral movement or privilege escalation. This activity is critical for detection engineering teams to monitor, as it often precedes more destructive actions in the cluster environment. The risk associated with this activity is particularly high in environments where RBAC is overly permissive or where service accounts are exposed to unauthorized actors.

## Impact

Successful reconnaissance of cluster permissions allows attackers to map the attack surface of the Kubernetes API, leading to potential unauthorized data access, persistence within the cluster, and full cluster compromise. This behavior is commonly observed during the discovery phase of container-focused campaigns, where attackers aim to move beyond an initial compromised pod.

## Recommendation

Prioritize the implementation of process-level monitoring for kubectl command-line arguments to distinguish between routine administrative tasks and potential reconnaissance.

- Deploy the Sigma rule below to detect 'kubectl auth can-i' usage on Linux and macOS nodes.
- Review RBAC configurations to ensure that service accounts are strictly limited to the permissions required for their specific function (Least Privilege).
- Implement time-based exceptions for automated CI/CD pipelines or scheduled audit scripts that legitimately use permission verification tools.
- Audit logs from the Kubernetes API server for high-frequency or anomalous 'subjectaccessreviews' requests, which correspond to the 'auth can-i' command.
