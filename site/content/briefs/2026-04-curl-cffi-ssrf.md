---
title: curl_cffi SSRF Vulnerability via Redirects
slug: 2026-04-curl-cffi-ssrf
description: curl_cffi versions before 0.15.0 are vulnerable to server-side request forgery (SSRF) due to unrestricted redirects to internal IP ranges, potentially enabling access to sensitive internal resources and cloud metadata.
date: "2026-04-03T21:36:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - curl_cffi
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-68616
    cvss: 7.5
    epss: 0.00061
references:
  - https://github.com/advisories/GHSA-qw2m-4pqf-rmpp
iocs:
  - type: ip
    value: 169.254.0.0
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: attacker.example
ioc_counts:
  domain: 1
  ip: 2
rules:
  - title: Detect curl_cffi Process Accessing Metadata Endpoint
    description: Detects processes using curl_cffi making network connections to the cloud metadata endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect HTTP Redirects to Internal IP Ranges
    description: Detects HTTP 302 redirects to internal IP ranges, indicating a potential SSRF attempt.
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

The curl_cffi library, a Python binding for libcurl, is susceptible to a server-side request forgery (SSRF) vulnerability in versions prior to 0.15.0. This flaw stems from the library's unrestricted handling of redirects, allowing attacker-controlled URLs to redirect requests to internal IP ranges and services. An attacker can exploit this behavior to access sensitive information such as cloud metadata or bypass network controls. The vulnerability is triggered because curl_cffi automatically follows redirects (CURLOPT_FOLLOWLOCATION = 1) without validating the destination. Additionally, the TLS impersonation feature in curl_cffi can further obscure malicious requests by mimicking legitimate browser traffic, potentially bypassing TLS-based filtering mechanisms. This issue is similar to other redirect-based SSRF vulnerabilities, like CVE-2025-68616.

## Attack Chain

1.  Attacker identifies a curl_cffi application vulnerable to SSRF.
2.  The attacker crafts a malicious URL pointing to an attacker-controlled server (attacker.example).
3.  The victim application uses curl_cffi to request the attacker-controlled URL.
4.  The attacker's server responds with an HTTP 302 redirect to an internal IP address (e.g., 169.254.169.254, the cloud metadata endpoint).
5.  curl_cffi automatically follows the redirect without validation.
6.  The request is sent to the internal IP address, bypassing external access controls.
7.  The internal service (e.g., cloud metadata API) responds with sensitive information.
8.  The attacker retrieves the sensitive information from the victim application's logs or response data.

## Impact

Successful exploitation of this vulnerability allows an attacker to access internal network services and sensitive cloud metadata. This can lead to the exposure of API keys, credentials, and other confidential information. The impact can range from unauthorized access to internal applications and data to potential compromise of cloud infrastructure. All applications using curl_cffi versions before 0.15.0 are vulnerable. The severity is high due to the potential for significant data breaches and infrastructure compromise.

## Recommendation

*   Upgrade to curl_cffi version 0.15.0 or later to patch CVE-2026-33752.
*   Implement server-side input validation to prevent passing attacker-controlled URLs to curl_cffi.
*   Monitor network traffic for connections to internal IP ranges (127.0.0.1, 169.254.0.0/16) originating from processes using curl_cffi.  Create a network_connection rule to detect this activity.
*   Inspect web server logs for HTTP 302 redirects to internal IP addresses, which could indicate SSRF attempts. Deploy a webserver rule to detect this.
