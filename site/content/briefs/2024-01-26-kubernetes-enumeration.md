---
title: Kubernetes Endpoint Permission Enumeration
slug: 2024-01-26-kubernetes-enumeration
description: A single user and source IP attempts to enumerate Kubernetes endpoints, issuing API requests across multiple endpoints to identify accessible resources for further exploitation.
date: "2026-03-05T13:13:30Z"
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

This detection identifies potential endpoint enumeration attempts within a Kubernetes environment. An attacker, or a compromised account, may attempt to map accessible resources within the Kubernetes cluster by issuing a burst of API calls across multiple endpoints from a single user and source IP address. This is achieved through a combination of both successful and failed API requests.  The behavior is not typical of normal Kubernetes cluster operation. Attackers leverage this reconnaissance…
