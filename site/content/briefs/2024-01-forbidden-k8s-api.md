---
title: Forbidden Direct Interactive Kubernetes API Request
slug: 2024-01-forbidden-k8s-api
description: This rule detects forbidden direct interactive Kubernetes API requests by correlating interactive command execution inside a container with explicitly forbidden Kubernetes API requests, indicating potential enumeration and privilege testing for lateral movement.
date: "2024-01-03T12:00:00Z"
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
vendors:
  - Kubernetes
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
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_d4c_k8s_mda_forbidden_direct_interactive_kubernetes_api_request.toml
rules:
  - title: Forbidden Direct Interactive Kubernetes API Request - Process Execution
    description: Detects interactive processes executing common Kubernetes tools in containers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Forbidden Direct Interactive Kubernetes API Request - Audit Log
    description: Detects 'forbid' decisions in Kubernetes audit logs related to interactive sessions.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1613
    data_sources:
      - webserver
      - linux
  - title: Forbidden Direct Interactive Kubernetes API Request - EQL Correlation
    description: Correlates process execution with forbidden Kubernetes API requests using EQL (simulated).
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.004
      - T1609
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection rule identifies instances where interactive commands executed within a container environment are associated with forbidden Kubernetes API requests. The rule leverages both Defend for Containers and Kubernetes audit logs to correlate command executions with API access attempts. Specifically, it focuses on scenarios where tools like `kubectl`, `curl`, or `openssl` are used interactively within a container, and those actions result in a "forbidden" response from the Kubernetes API server. This activity often signifies attempts to enumerate cluster resources, test permissions, or facilitate lateral movement within the Kubernetes environment. The rule was created on 2026/01/21, and updated on 2026/04/10. It is applicable to environments leveraging Elastic Stack version 9.3.0 or later with the cloud_defend and kubernetes integrations.

## Attack Chain

1. An attacker gains initial access to a container within a Kubernetes cluster, potentially through a compromised application or vulnerability exploitation.
2. The attacker initiates an interactive shell (e.g., `bash`, `sh`) within the compromised container.
3. The attacker uses command-line tools like `kubectl`, `curl`, or `openssl` within the interactive shell to interact with the Kubernetes API server.
4. The attacker attempts to enumerate cluster resources or test permissions by sending API requests for resources like pods, services, or secrets.
5. The Kubernetes API server evaluates the request based on configured RBAC policies and determines that the attacker lacks the necessary permissions.
6. The API server returns a "forbidden" response (HTTP 403) to the request.
7. Audit logs record the forbidden API request, including details about the user, resource, and reason for denial.
8. The attacker may attempt further exploitation or lateral movement based on the information gathered (or lack thereof) during the discovery phase.

## Impact

A successful attack following this pattern could lead to unauthorized access to sensitive data, lateral movement within the cluster, and potentially full cluster compromise. While the detected activity is "forbidden," it indicates reconnaissance efforts and probing for weaknesses. If successful, attackers may gain access to secrets, manipulate deployments, or disrupt services. It is crucial to investigate these forbidden requests as they often precede more damaging actions.

## Recommendation

*   Deploy the Sigma rule "Forbidden Direct Interactive Kubernetes API Request" to detect suspicious interactive command executions correlated with forbidden Kubernetes API requests. Enable both `logs-cloud_defend.process*` and `logs-kubernetes.audit_logs-*` indices to activate the rule.
*   Review Kubernetes RBAC configurations to ensure least privilege and prevent unauthorized access to sensitive resources. Contact the workload owner.
*   Implement network policies to restrict outbound connections from containers, limiting their ability to directly access the Kubernetes API server.
*   Harden container images by removing unnecessary tools like `kubectl`, `curl`, and `openssl` to reduce the attack surface.
*   Monitor container activity for unexpected command executions or API access attempts using Defend for Containers or similar solutions.
