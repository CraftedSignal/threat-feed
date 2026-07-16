---
title: Server-Side Request Forgery in text-generation-inference Allows Internal Access
slug: 2026-07-text-generation-inference-ssrf
description: An unauthenticated network attacker can exploit a Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-63086, in the OpenAI-compatible multimodal chat completions endpoint of text-generation-inference through version 3.3.7 to coerce the server into issuing arbitrary HTTP GET requests, enabling internal port scanning and credential theft from internal services and cloud instance metadata endpoints.
date: "2026-07-16T17:21:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - data-exfiltration
  - cloud
  - network
vendors:
  - Hugging Face
products:
  - text-generation-inference <= 3.3.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated network attackers to coerce the server into issuing arbitrary HTTP GET requests
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: enabling attackers to bypass scheme checks via redirect chains to reach internal services and cloud instance-metadata endpoints for internal port scanning
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: enabling attackers to bypass scheme checks via redirect chains to reach internal services and cloud instance-metadata endpoints for ... credential theft
    confidence_band: high
cves:
  - id: CVE-2026-63086
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63086
rules:
  - title: Detect Possible SSRF to Internal/Metadata IPs
    description: Detects CVE-2026-63086 exploitation - Outbound network connections from server processes to private IP ranges, loopback addresses, or cloud instance metadata service IP addresses, indicative of Server-Side Request Forgery (SSRF) attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - reconnaissance
    techniques:
      - T1552
      - T1595.002
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

A critical Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-63086, has been identified in text-generation-inference software, affecting all versions through 3.3.7. This vulnerability resides within the OpenAI-compatible multimodal chat completions endpoint, allowing unauthenticated network attackers to compromise the server. By supplying a specially crafted `image_url` value within chat message content, attackers can coerce the server into making arbitrary HTTP GET requests. The root cause is a lack of validation in the `fetch_image` function within `router/src/validation.rs` for private, loopback, link-local, or cloud metadata target addresses. Additionally, the `reqwest` HTTP client's default behavior of following redirects enables attackers to bypass scheme checks through redirect chains. This exploitation vector leads to internal port scanning and credential theft from internal services and cloud instance-metadata endpoints, posing a significant risk of unauthorized access and data exfiltration within an organization's network.

## Attack Chain

1. An unauthenticated attacker identifies a `text-generation-inference` instance exposed on the network, specifically its OpenAI-compatible multimodal chat completions endpoint.
2. The attacker crafts a malicious HTTP POST request targeting the `/v1/chat/completions` endpoint on the vulnerable server.
3. The request's JSON body includes chat message content that contains a specially crafted `image_url` value pointing to an attacker-controlled server (e.g., `http://attacker.com/redirect?to=169.254.169.254`).
4. The `text-generation-inference` server, within its `fetch_image` function in `router/src/validation.rs`, attempts to retrieve the image specified by the malicious `image_url`.
5. Due to insufficient validation of private, loopback, link-local, or cloud metadata target addresses, and the HTTP client's default behavior of following redirects, the server is coerced.
6. The server makes an arbitrary HTTP GET request to an internal resource or a cloud instance-metadata endpoint (e.g., `169.254.169.254`) as directed by the attacker's crafted URL and subsequent redirects.
7. The internal service or metadata endpoint responds to the `text-generation-inference` server with information, which may include sensitive data like cloud credentials or internal network details.
8. The attacker retrieves this response via the initial `/v1/chat/completions` request, completing credential theft or internal network reconnaissance.

## Impact

Successful exploitation of CVE-2026-63086 grants unauthenticated attackers the ability to perform internal network reconnaissance, such as port scanning, and potentially steal credentials from cloud instance metadata endpoints. This can lead to unauthorized access to internal services, sensitive data exfiltration, and further compromise of the victim's infrastructure. While no specific victim count or targeted sectors are mentioned, any organization deploying text-generation-inference through version 3.3.7 with its OpenAI-compatible multimodal chat completions endpoint exposed is at risk.

## Recommendation

* Patch CVE-2026-63086 immediately by upgrading `text-generation-inference` to a version beyond 3.3.7.
* Implement network segmentation to restrict outbound network connections from `text-generation-inference` instances, especially to private IP ranges and cloud metadata endpoints.
* Deploy the Sigma rule "Detect Possible SSRF to Internal/Metadata IPs" in this brief to your SIEM and tune for your environment to identify suspicious outbound connections from servers running `text-generation-inference`.
* Ensure Sysmon or equivalent network connection logging is enabled on servers hosting `text-generation-inference` to activate the rules above.
