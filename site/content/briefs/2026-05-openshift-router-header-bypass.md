---
title: 'OpenShift Router Vulnerability CVE-2026-46579: Mutual TLS Bypass via Header Injection'
slug: 2026-05-openshift-router-header-bypass
description: CVE-2026-46579 describes a vulnerability in the Red Hat OpenShift Router. When a Route is configured with `insecureEdgeTerminationPolicy` set to Allow, the HTTP frontend fails to remove `X-SSL-Client-*` headers from incoming requests, allowing unauthenticated attackers to bypass mutual TLS authentication and impersonate client certificate identities.
date: "2026-05-29T11:18:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openshift
  - mtls
  - header-injection
  - cve-2026-46579
vendors:
  - Red Hat
products:
  - OpenShift Router
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1587
    technique_name: Develop Capabilities
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1587
    technique_name: Develop Capabilities
cves:
  - id: CVE-2026-46579
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46579
rules:
  - title: Detect OpenShift Router mTLS Bypass Attempt via X-SSL-Client Headers
    description: Detects CVE-2026-46579 exploitation — HTTP request containing X-SSL-Client-* headers when mutual TLS is expected, indicating a potential attempt to bypass authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1587
      - T1587.001
    data_sources:
      - webserver
rules_count: 1
---

The OpenShift Router is susceptible to a critical security flaw identified as CVE-2026-46579. This vulnerability exists when a Route within OpenShift is configured with the `insecureEdgeTerminationPolicy` set to "Allow". In this configuration, the HTTP frontend of the Router fails to sanitize incoming requests by removing potentially malicious `X-SSL-Client-*` headers. This oversight enables an unauthenticated attacker to craft and inject arbitrary `X-SSL-Client-*` headers into plain HTTP requests. The vulnerability allows bypassing mutual TLS (mTLS) authentication mechanisms and impersonating legitimate client certificate identities. This issue poses a significant risk to applications relying on mTLS for secure communication, as it can lead to unauthorized access and data compromise.

## Attack Chain

1. An attacker identifies an OpenShift Route configured with `insecureEdgeTerminationPolicy` set to "Allow".
2. The attacker crafts a plain HTTP request containing malicious `X-SSL-Client-*` headers.
3. The attacker sends the crafted HTTP request to the OpenShift Router.
4. The Router, due to the misconfiguration, forwards the request with the attacker-controlled `X-SSL-Client-*` headers to the backend service.
5. The backend service, incorrectly trusting the `X-SSL-Client-*` headers due to the lack of sanitization by the Router, authenticates the attacker as a legitimate client.
6. The attacker gains unauthorized access to the backend service, impersonating the client certificate identity.
7. The attacker performs unauthorized actions, such as accessing sensitive data or executing privileged operations.

## Impact

Successful exploitation of CVE-2026-46579 allows an unauthenticated attacker to bypass mutual TLS authentication in OpenShift environments. This can lead to unauthorized access to sensitive resources, privilege escalation, and data breaches. The number of affected deployments depends on the prevalence of the vulnerable `insecureEdgeTerminationPolicy` configuration. Organizations relying on mutual TLS for securing backend services are at significant risk.

## Recommendation

*   Apply the latest security patches to the OpenShift Router to address CVE-2026-46579.
*   Review all OpenShift Route configurations to ensure that `insecureEdgeTerminationPolicy` is not set to "Allow" where mutual TLS authentication is required.
*   Implement the Sigma rule "Detect OpenShift Router mTLS Bypass Attempt via X-SSL-Client Headers" to detect attempts to exploit this vulnerability.
*   Monitor web server logs for suspicious `X-SSL-Client-*` headers originating from unexpected sources or containing unusual values.
