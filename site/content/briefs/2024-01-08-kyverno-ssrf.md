---
title: Kyverno SSRF Vulnerability in CEL HTTP Library
slug: 2024-01-08-kyverno-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in Kyverno's CEL HTTP library allows users with namespace-scoped policy creation permissions to make arbitrary HTTP requests, enabling unauthorized access to internal services, cloud metadata endpoints, and data exfiltration.
date: "2026-04-14T22:37:20Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - SSRF
  - kyverno
  - kubernetes
  - cel
  - cloud-security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-4789
    cvss: 9.8
    epss: 0.0002
references:
  - https://github.com/advisories/GHSA-rggm-jjmc-3394
iocs:
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: internal-api.kube-system.svc.cluster.local
  - type: email
    value: igor.stepansky@orca.security
  - type: email
    value: stepanskyigor@gmail.com
ioc_counts:
  domain: 1
  email: 2
  ip: 1
rules:
  - title: Detect Kyverno NamespacedValidatingPolicy Using http.Get/http.Post
    description: Detects the creation of a NamespacedValidatingPolicy that uses the http.Get or http.Post functions, which could indicate a potential SSRF attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - auditd
      - linux
  - title: Detect Outbound Connections from Kyverno Pods to Metadata Endpoint
    description: Detects network connections originating from Kyverno pods to the cloud metadata endpoint (169.254.169.254), which could indicate SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A Server-Side Request Forgery (SSRF) vulnerability has been identified in Kyverno's CEL HTTP library (`pkg/cel/libs/http/`), affecting versions >= 1.16.0. This flaw allows users with permissions to create namespace-scoped policies to bypass intended restrictions and make arbitrary HTTP requests from the Kyverno admission controller. This can lead to unauthorized access to internal Kubernetes services in other namespaces, cloud metadata endpoints such as 169.254.169.254 (allowing credential theft), and the exfiltration of sensitive data by embedding it in policy error messages. The vulnerability stems from a lack of URL validation in the `http.Get()` and `http.Post()` functions used within CEL policies, contrasting with the namespace enforcement present in the `resource.Lib`. The reported vulnerability was tested and confirmed on Kyverno v1.16.2 deployed via Helm chart 3.6.2.

## Attack Chain

1. An attacker gains the ability to create NamespacedValidatingPolicy resources within a specific Kubernetes namespace. This could be achieved through compromised credentials, misconfigured RBAC, or other privilege escalation methods.
2. The attacker crafts a malicious NamespacedValidatingPolicy that utilizes the `http.Get()` or `http.Post()` function within a CEL expression. The crafted policy is applied to the target Kubernetes cluster.
3. The CEL expression within the policy is designed to make an HTTP request to an internal service (e.g., `internal-api.kube-system.svc.cluster.local`) or a cloud metadata endpoint (`169.254.169.254`).
4. The crafted NamespacedValidatingPolicy is triggered by a specific event, such as the creation of a ConfigMap within the attacker's namespace, which matches the `matchConstraints` defined in the policy.
5. The Kyverno admission controller executes the CEL expression, making the HTTP request to the specified internal service or cloud metadata endpoint.
6. The HTTP response from the internal service or cloud metadata endpoint is captured by the CEL expression.
7. The attacker crafts a `messageExpression` within the NamespacedValidatingPolicy to include the captured data in a validation error message.
8. The validation error message, containing the exfiltrated data, is returned to the user, effectively leaking sensitive information.

## Impact

This SSRF vulnerability allows attackers with limited, namespace-scoped privileges to access sensitive data within a Kubernetes cluster. This includes the ability to access services in other namespaces, potentially compromising sensitive configurations or secrets. Access to cloud metadata endpoints (169.254.169.254) allows the theft of IAM credentials, leading to further escalation of privileges within the cloud environment. Successful exploitation breaks namespace isolation, undermining the security model of Kyverno and Kubernetes.

## Recommendation

*   Deploy the Sigma rule to detect suspicious usage of `http.Get` or `http.Post` function in `NamespacedValidatingPolicy` resources in your SIEM and tune for your environment.
*   Monitor network connections originating from the Kyverno pods, specifically looking for connections to internal Kubernetes services or cloud metadata endpoints (169.254.169.254), using the `network_connection` log source.
*   Apply the suggested fix by adding namespace and URL restrictions to `pkg/cel/libs/http/http.go` in Kyverno, similar to how `resource.Lib` enforces namespace boundaries as per the advisory.
*   Upgrade Kyverno to a patched version >= 1.17 when available, addressing the CVE-2026-4789.
