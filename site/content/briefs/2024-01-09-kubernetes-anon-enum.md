---
title: Kubernetes Potential Endpoint Permission Enumeration by Anonymous User
slug: 2024-01-09-kubernetes-anon-enum
description: An anonymous user attempts to enumerate Kubernetes API endpoints, resulting in a series of failed API requests across multiple endpoints, potentially revealing the cluster's exposed surface.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - discovery
  - enumeration
  - cloud
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Gather Victim Identity Information
references:
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#unauthenticated-api-access
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/discovery_endpoint_permission_enumeration_by_anonymous_user.toml
rules:
  - title: Kubernetes Anonymous User Discovery Attempt
    description: Detects a burst of Kubernetes API requests from an unauthenticated identity probing many different endpoints, producing mostly forbidden/unauthorized/not found responses within a small window.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - auditd
      - kubernetes
  - title: Kubernetes Unauthenticated User Discovery Attempt
    description: Detects a burst of Kubernetes API requests from an unauthenticated identity probing many different endpoints, producing mostly forbidden/unauthorized/not found responses within a small window.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

This detection identifies potential endpoint enumeration attempts within a Kubernetes environment by an anonymous user, who lacks authentication or authorization to access the Kubernetes API server. The rule focuses on detecting a sequence of failed API requests targeting various endpoints, indicating a possible automated permission enumeration. This behavior is atypical for standard Kubernetes operations. Attackers may leverage this technique to map the cluster’s exposed surface, gaining insights into accessible APIs before committing to further malicious activities like credential theft or exploitation. The targeted resources can include core resources like pods, secrets, namespaces, and custom resources. The detection is based on audit logs, which should be enabled for a Kubernetes cluster.

## Attack Chain

1.  An attacker gains unauthenticated network access to the Kubernetes API server.
2.  The attacker sends a series of GET/LIST requests to various Kubernetes API endpoints (e.g., /api/v1/pods, /api/v1/secrets, /apis/rbac.authorization.k8s.io/v1/roles).
3.  The API server evaluates the requests and, due to the lack of authentication or authorization, returns "401 Unauthorized", "403 Forbidden", or "404 Not Found" errors.
4.  The attacker iterates through different resource types (e.g., pods, secrets, namespaces, CRDs) using automated scripting or tooling.
5.  The attacker analyzes the API responses to identify accessible endpoints and resources.
6.  Based on the discovered information, the attacker pivots to more targeted attacks, such as attempting to exploit identified vulnerabilities or gaining unauthorized access to sensitive data.

## Impact

Successful enumeration can expose the cluster's attack surface, enabling attackers to identify potential vulnerabilities and accessible resources. This information can be used to craft targeted attacks, potentially leading to unauthorized access, data breaches, or denial-of-service attacks. While the enumeration itself doesn't directly cause damage, it provides critical reconnaissance data for subsequent malicious activities. The risk is elevated if the API server is publicly accessible.

## Recommendation

*   Enable Kubernetes audit logging to capture API server requests and responses, which are essential for this detection (reference the `logs-kubernetes.audit_logs-*` index in the query).
*   Disable anonymous authentication on the API server to prevent unauthenticated users from accessing the API (see references for remediation steps).
*   Review and restrict network access to the Kubernetes API server, allowing only authorized IPs or networks to connect (reference the overview section).
*   Deploy the provided Sigma rule to your SIEM to detect potential endpoint enumeration attempts by anonymous users (`Kubernetes Potential Endpoint Permission Enumeration Attempt by Anonymous User Detected`).
*   Harden RBAC configurations to ensure least-privilege access, preventing anonymous or unauthenticated users from gaining unauthorized permissions (reference overview and remediation sections).
