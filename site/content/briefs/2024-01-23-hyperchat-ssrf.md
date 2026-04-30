---
title: BigSweetPotatoStudio HyperChat AI Proxy Middleware Server-Side Request Forgery
slug: 2024-01-23-hyperchat-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in BigSweetPotatoStudio HyperChat up to version 2.0.0-alpha.63, allowing a remote attacker to manipulate the 'baseurl' argument in the 'fetch' function of the AI Proxy Middleware component to make arbitrary HTTP requests.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - webserver
vendors:
  - BigSweetPotatoStudio
products:
  - HyperChat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7223
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7223
rules:
  - title: HyperChat SSRF Attempt
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in BigSweetPotatoStudio HyperChat by monitoring HTTP requests containing suspicious baseurl parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: HyperChat SSRF Attempt External
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in BigSweetPotatoStudio HyperChat by monitoring HTTP requests containing suspicious external baseurl parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-7223, affects BigSweetPotatoStudio HyperChat up to version 2.0.0-alpha.63. The vulnerability resides in the 'fetch' function within the AI Proxy Middleware located at `packages/core/src/http/aiProxyMiddleware.mts`. By manipulating the `baseurl` argument, a remote attacker can force the server to make arbitrary HTTP requests to internal or external resources. This issue allows attackers to potentially access sensitive information, bypass security controls, or perform other malicious actions. The vulnerability is remotely exploitable, and a public exploit is available, increasing the risk of widespread exploitation. The project maintainers were notified but have not responded.

## Attack Chain

1. The attacker identifies an instance of BigSweetPotatoStudio HyperChat running version 2.0.0-alpha.63 or earlier.
2. The attacker crafts a malicious HTTP request targeting the AI Proxy Middleware component.
3. The crafted request includes a manipulated `baseurl` argument within the request to the `fetch` function, pointing to an internal resource (e.g., `http://localhost:8080/admin`) or an external server controlled by the attacker.
4. The HyperChat server, without proper validation of the `baseurl`, uses it to make an HTTP request.
5. If the `baseurl` points to an internal resource, the server retrieves the content of that resource and sends it back to the attacker.
6. If the `baseurl` points to an external server, the server makes a request to the attacker's server, potentially leaking sensitive information in the request headers or body.
7. The attacker analyzes the response from the server to gather sensitive information or identify further attack vectors.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-7223) can allow an attacker to read sensitive internal data, such as configuration files or API keys, potentially leading to full system compromise. The attacker could also use the vulnerable server as a proxy to scan internal networks or attack other internal systems. Due to the public availability of the exploit, organizations using vulnerable versions of HyperChat are at increased risk of being targeted. The CVSS v3.1 base score for this vulnerability is 7.3, indicating a high severity.

## Recommendation

*   Apply appropriate input validation and sanitization to the `baseurl` argument in the AI Proxy Middleware to prevent manipulation, addressing CVE-2026-7223.
*   Implement network segmentation to restrict access from the HyperChat server to only necessary internal resources.
*   Deploy the Sigma rule "HyperChat SSRF Attempt" to detect attempts to exploit the vulnerability via HTTP request patterns.
*   Monitor web server logs for suspicious outbound connections originating from the HyperChat server, correlating with user input.
