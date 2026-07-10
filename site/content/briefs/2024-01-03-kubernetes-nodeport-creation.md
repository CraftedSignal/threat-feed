---
title: Kubernetes NodePort Service Creation Detected
slug: 2024-01-03-kubernetes-nodeport-creation
description: Detection of a Kubernetes NodePort service creation, potentially exposing internal services to the external network, monitored via Kubernetes Audit logs, and indicating a threat to the Kubernetes infrastructure's integrity and security.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - cloud
  - network
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
rules:
  - title: Kubernetes NodePort Service Creation Detected
    description: Detects the creation of a Kubernetes NodePort service by monitoring Kubernetes audit logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - webserver
      - linux
  - title: Kubernetes NodePort Creation - Suspicious User Agent
    description: Detects Kubernetes NodePort creation with a suspicious user agent.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert focuses on detecting the creation of Kubernetes NodePort services. NodePorts expose internal services to the external network, which can be a legitimate configuration in some environments, but it can also represent a significant security risk if implemented maliciously. This activity is detected by monitoring Kubernetes Audit logs for the creation of NodePort services. The alert is triggered when a new NodePort service is created within the Kubernetes cluster, as reflected in the audit logs. While no specific campaign or actor is identified, the creation of a NodePort should be investigated to ensure it aligns with expected behavior and is not a result of unauthorized access or misconfiguration. This can lead to data breaches, service disruptions, or unauthorized access to sensitive information.

## Attack Chain

1.  An attacker gains initial access to a Kubernetes cluster, potentially through compromised credentials or a vulnerability in a deployed application.
2.  The attacker authenticates to the Kubernetes API server.
3.  The attacker crafts a request to create a new service of type NodePort.
4.  The attacker submits the request to the Kubernetes API server.
5.  The Kubernetes API server validates the request and creates the NodePort service.
6.  The Kubernetes Audit log records the creation of the NodePort service, including details about the user, source IP, and the service configuration.
7.  External traffic can now reach the service via the NodePort, potentially bypassing intended security controls.
8.  The attacker leverages the exposed service to perform unauthorized actions or access sensitive data.

## Impact

Successful exploitation via NodePort creation could expose sensitive internal services to the public internet. This may allow unauthorized access to databases, internal applications, or other critical systems, potentially leading to data breaches, service disruption, or full compromise of the Kubernetes cluster. The severity depends on the nature of the exposed service and the level of access the attacker gains.

## Recommendation

*   Enable Kubernetes audit logging to capture API server requests as described in the "how_to_implement" section, focusing on the `kube_audit` data source.
*   Deploy the Sigma rule `Kubernetes NodePort Service Creation Detected` to identify unauthorized NodePort service creation.
*   Investigate any alerts triggered by the `Kubernetes NodePort Service Creation Detected` Sigma rule, focusing on the `user` and `src_ip` fields to identify the source of the request.
*   Review and validate all existing NodePort services to ensure they are necessary and properly secured.
*   Implement network policies to restrict access to NodePort services from unauthorized sources.
*   Monitor `src_ip` from the audit logs as a potential IOC if malicious activity is confirmed after NodePort creation.
