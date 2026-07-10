---
title: Direct Interactive Kubernetes API Request by Common Utilities
slug: 2024-01-09-k8s-api-request
description: This rule detects direct interactive Kubernetes API requests by common utilities from within a container, potentially indicating lateral movement or discovery activities within the cluster.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - container
  - execution
  - discovery
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_d4c_k8s_mda_direct_interactive_kubernetes_api_request_by_usual_utilities.toml
rules:
  - title: Interactive Kubernetes API Request via Kubectl
    description: Detects interactive kubectl execution within a container followed by a Kubernetes API audit event, indicating potential reconnaissance or lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.004
      - T1613
    data_sources:
      - process_creation
      - linux
  - title: Container Network Utility API Access
    description: Detects curl/wget/openssl/socat/ncat commands executed interactively within a container correlated with Kubernetes API audit logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.004
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies instances where common utilities such as `wget`, `curl`, `openssl`, `socat`, `ncat`, or `kubectl` are executed interactively within a container, followed by a Kubernetes API response. This behavior can signify that an attacker has compromised a pod and is attempting to leverage the pod's service account token to query Kubernetes API endpoints, potentially for reconnaissance or lateral movement purposes. The rule is designed to correlate container executions of these utilities with Kubernetes API responses, highlighting suspicious activities indicative of hands-on-keyboard access to the API server. The rule was initially created in January 2026 and updated in April 2026. It requires Elastic stack version 9.3.0 or later with the Defend for Containers and Kubernetes integrations.

## Attack Chain

1. An attacker compromises a container within a Kubernetes pod, potentially through an application vulnerability or misconfiguration.
2. The attacker gains shell access to the compromised container.
3. The attacker accesses the pod's mounted service account token, typically located at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
4. The attacker uses a common utility like `curl` or `kubectl` within the container to interact with the Kubernetes API server. They may target endpoints such as `/api` or `/apis` to enumerate available resources.
5. The Kubernetes API server receives the request and processes it, generating an audit log entry.
6. The API server responds to the request, potentially revealing information about pods, secrets, or other sensitive resources within the cluster.
7. The attacker analyzes the API responses to map the cluster scope and identify potential targets for lateral movement or data exfiltration.
8. The attacker may use the gathered information to escalate privileges or access other resources within the Kubernetes cluster, leading to further compromise.

## Impact

A successful attack can lead to the exposure of sensitive information, such as secrets or configuration data, and potential lateral movement within the Kubernetes cluster. This can allow an attacker to compromise other pods, services, or even the entire cluster, leading to data breaches, service disruption, or other malicious activities. The severity is medium, assuming the attacker can only read API objects.

## Recommendation

*   Deploy the Sigma rule to your SIEM and tune for your environment to detect suspicious interactive API requests from containers.
*   Review Kubernetes audit logs for API requests originating from pods where common utilities are executed interactively.
*   Implement network policies to restrict pod egress traffic, limiting the ability of compromised containers to reach the Kubernetes API server.
*   Harden containers by removing unnecessary utilities like `curl`, `wget`, and `kubectl` to reduce the attack surface.
*   Enable admission controls (Pod Security Admission, Gatekeeper, or Kyverno) to block shells or kubectl/netcat in images as described in the rule's note.
*   Revoke and rotate the service account credentials used by the implicated pod, invalidate the token at `/var/run/secrets/kubernetes.io/serviceaccount/token`, and remove excess RoleBindings or ClusterRoleBindings tied to that identity as described in the rule's note.
