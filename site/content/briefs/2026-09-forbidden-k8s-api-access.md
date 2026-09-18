---
title: Detection of Unauthorized Interactive Kubernetes API Probing
slug: 2026-09-forbidden-k8s-api-access
description: Adversaries performing hands-on-keyboard enumeration within compromised containers are detected by correlating interactive process execution with forbidden Kubernetes API audit responses.
date: "2026-09-18T19:15:00Z"
lastmod: "2026-09-18T19:15:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - discovery
  - kubernetes
  - cloud-native
  - container-security
  - container
  - threat-detection
vendors:
  - Kubernetes
products:
  - Kubernetes (all versions)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule leverages a combination of Defend for Containers and Kubernetes audit logs to detect the execution of forbidden interactive Kubernetes API requests.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: An adversary may need to execute interactive Kubernetes API requests to gain access to the Kubernetes API server or other resources within the cluster.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: These requests are often used to enumerate the Kubernetes API server or other resources within the cluster, and may indicate an attempt to move laterally within the cluster.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
  immediate_actions:
    - action: Deploy EQL correlation rule to detect forbidden API requests from interactive shell sessions
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 5d1c962d-5d2a-48d4-bdcf-e980e3914947
  mitigation_plan:
    - priority: short_term
      action: Restrict egress from containers to API server using NetworkPolicy
      owner: Cloud Security Team
      addresses: T1613
      evidence: Response and remediation section
updates:
  - at: "2026-09-18T19:15:09Z"
    level: L1
    summary: added coverage for Kubernetes (all versions)
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_d4c_k8s_mda_kubernetes_api_activity_by_unusual_utilities.toml
---

This detection pattern identifies unauthorized interactive access attempts within a Kubernetes cluster. When an attacker gains access to a container, they often utilize shell environments to perform discovery and lateral movement. By leveraging utilities such as kubectl, curl, or openssl, attackers attempt to communicate with the Kubernetes API server to enumerate resources, probe for secrets, or test service account privileges. Because these actions are often performed by under-privileged accounts or against sensitive endpoints, they result in 'forbid' decisions within the Kubernetes audit logs. This rule provides a mechanism for detection engineers to correlate the specific interactive shell activity within a container with these denied API requests, identifying potential hands-on-keyboard probing even when the attacker lacks the necessary permissions to succeed. This visibility is critical for identifying compromised workloads that are being repurposed for cluster-level discovery.

## Attack Chain

1. Attacker gains initial access to a container process (e.g., via web application exploit).
2. Attacker executes an interactive shell (e.g., /bin/bash or /bin/sh) within the container.
3. Attacker identifies native tooling within the container (e.g., kubectl, curl, openssl) or drops malicious binaries.
4. Attacker uses the container's mounted ServiceAccount token to initiate an API request to the Kubernetes API server.
5. API request is sent from the pod to the API server endpoint (e.g., https://kubernetes.default.svc).
6. Kubernetes authorization policy evaluates the request and returns an HTTP 403 Forbidden status.
7. Audit logs record the forbidden action associated with the specific pod identity.
8. Security monitoring platform correlates the local shell activity with the denied API audit log.

## Impact

Successful unauthorized discovery can provide an attacker with a map of the cluster's network, services, and secrets. If the attacker successfully leverages an over-privileged service account, they may escalate privileges or pivot to other nodes within the cluster. This activity indicates a breakdown in container isolation and least-privilege RBAC.

## Recommendation

- Enable Kubernetes Audit Logging and stream to the SIEM to support the audit correlation logic described in this brief.
- Deploy the EQL detection logic to identify unauthorized interactive attempts originating from pods.
- Implement NetworkPolicies that restrict egress from non-admin containers to the Kubernetes API server IP addresses.
- Perform regular audits of ServiceAccount permissions, ensuring pods only possess the minimal RBAC roles required for their function.
- Rebuild container images to exclude administrative tooling (kubectl, curl, nmap, socat) where such functionality is not required for application operation.
