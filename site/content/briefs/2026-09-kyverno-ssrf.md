---
title: Kyverno SSRF Vulnerability via Legacy API Call Executor
slug: 2026-09-kyverno-ssrf
description: Kyverno versions before 1.19.1 are vulnerable to Server-Side Request Forgery due to inadequate egress filtering in the legacy apiCall and GlobalContextEntry components, allowing attackers to access internal cloud metadata and cluster services using the Kyverno ServiceAccount token.
date: "2026-09-26T15:13:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-100705
    cvss: 7.6
---

Kyverno versions prior to 1.19.1 contain a critical SSRF vulnerability (CVE-2026-100705) originating from the legacy `apiCall` service executor and the `GlobalContextEntry` external-API path. Unlike newer CEL-based implementations, these components lack egress blocklisting for sensitive internal endpoints, including loopback addresses (127.0.0.0/8, ::1/128) and cloud metadata services (169.254.169.254, 169.254.169.253). 

An attacker with the ability to influence a `ClusterPolicy`, `GlobalContextEntry`, or an admission resource used by a templated policy can force the Kyverno controller to execute arbitrary GET or POST requests against internal cluster or cloud infrastructure. Furthermore, the executor incorrectly attaches the Kyverno ServiceAccount token to these requests. This allows an attacker to leverage Kyverno's network position to reach restricted internal services and potentially harvest cloud instance credentials. This vulnerability is of high importance as it allows for privilege escalation and internal network reconnaissance within a Kubernetes environment.

## Attack Chain

1. Attacker identifies an existing `ClusterPolicy` or `GlobalContextEntry` that utilizes the legacy `apiCall` mechanism.
2. Attacker modifies or submits an admission resource that templates the `service URL` used by the Kyverno policy.
3. Attacker triggers the policy engine by submitting a Kubernetes resource that initiates the vulnerable `apiCall` execution.
4. The Kyverno controller receives the request and executes the legacy `apiCall` service executor (pkg/engine/apicall/executor.go).
5. The executor performs an unvalidated outbound request to an attacker-specified internal endpoint or cloud metadata service.
6. The outgoing request includes the Kyverno `ServiceAccount` token, potentially exposing it to the destination endpoint.
7. The destination service processes the request, potentially returning metadata or data that the attacker can exfiltrate or use for further lateral movement.

## Impact

Successful exploitation allows attackers to bypass network segmentation to reach internal services not exposed externally, access cloud metadata services to retrieve sensitive instance metadata or credentials, and potentially use the Kyverno service account token to perform unauthorized actions within the Kubernetes cluster. This vulnerability impacts all organizations
