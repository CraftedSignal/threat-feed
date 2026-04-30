---
title: Kubernetes Endpoint Permission Enumeration
slug: 2024-01-26-kubernetes-enumeration
description: A single user and source IP attempts to enumerate Kubernetes endpoints, issuing API requests across multiple endpoints to identify accessible resources for further exploitation.
date: "2026-03-05T13:13:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - enumeration
  - discovery
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/discovery_endpoint_permission_enumeration_by_user_and_srcip.toml
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#unauthenticated-api-access
rules:
  - title: Kubernetes API Enumeration by User and IP
    description: Detects a single user and IP issuing a burst of API calls across many resources and URLs, indicating RBAC probing.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1613
    data_sources:
      - network_connection
      - kubernetes
  - title: Kubernetes Excessive API verbs from same source IP
    description: Detects a single source IP using multiple API verbs like get, list, and watch indicating potential enumeration
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1613
    data_sources:
      - network_connection
      - kubernetes
rules_count: 2
---

This detection identifies potential endpoint enumeration attempts within a Kubernetes environment. An attacker, or a compromised account, may attempt to map accessible resources within the Kubernetes cluster by issuing a burst of API calls across multiple endpoints from a single user and source IP address. This is achieved through a combination of both successful and failed API requests.  The behavior is not typical of normal Kubernetes cluster operation. Attackers leverage this reconnaissance to identify high-value targets like secrets, pods, or nodes before attempting privilege escalation or lateral movement. The rule specifically looks for unusual patterns in Kubernetes audit logs.

## Attack Chain

1.  The attacker gains initial access to the Kubernetes cluster, potentially through compromised credentials or a vulnerable application.
2.  The attacker uses `kubectl` or a similar tool to send a series of API requests.
3.  The attacker attempts to enumerate Kubernetes API endpoints using "get", "list", "watch", "create", "update", and "patch" verbs.
4.  The requests target a variety of resources, including pods, services, deployments, secrets, and nodes.
5.  The attacker analyzes the responses to identify endpoints and resources that are accessible with the current credentials. Successful and failed responses are both valuable for mapping permissions.
6.  The attacker identifies valuable targets, such as secrets or sensitive data stored in configmaps.
7.  The attacker attempts to escalate privileges by exploiting identified vulnerabilities or misconfigurations.
8.  The attacker moves laterally within the cluster to gain access to other resources or workloads.

## Impact

Successful enumeration can lead to privilege escalation, lateral movement, and data exfiltration within the Kubernetes cluster. Attackers can identify and compromise sensitive resources such as secrets, configmaps, and pods. The number of affected systems and the scope of the impact depend on the extent of the attacker's access and the sensitivity of the compromised resources.

## Recommendation

*   Enable Kubernetes audit logging to capture API server requests and responses, which is required for the provided rules and the original Elastic rule.
*   Deploy the Sigma rules provided below to your SIEM to detect enumeration attempts and tune them based on your environment.
*   Enforce the principle of least privilege by assigning appropriate RBAC roles to users and service accounts to limit potential enumeration damage.
*   Monitor Kubernetes audit logs for unusual API request patterns, specifically a high number of requests from a single user and IP address.
*   Review RBAC bindings for unexpected or overly broad access as mentioned in the overview.
*   Segment API access with network controls (private endpoint/VPN allowlists) as suggested in the response section of the overview.
