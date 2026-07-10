---
title: Tinyproxy HTTP Request Parsing Desynchronization Vulnerability (CVE-2026-31842)
slug: 2024-01-tinyproxy-desync
description: Tinyproxy versions 1.11.3 and earlier are vulnerable to HTTP request parsing desynchronization due to case-sensitive comparison of the Transfer-Encoding header, allowing unauthenticated remote attackers to cause denial of service or security control bypass by sending crafted requests.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - tinyproxy
  - http
  - desync
  - denial-of-service
  - CVE-2026-31842
  - linux
vendors:
  - Tinyproxy
products:
  - Tinyproxy
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0008
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Software Vulnerability
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint DoS
cves:
  - id: CVE-2026-31842
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31842
rules:
  - title: Detect Case-Variant Transfer-Encoding Header
    description: Detects HTTP requests with a Transfer-Encoding header that deviates from the standard 'chunked' value, indicating a potential attempt to exploit CVE-2026-31842.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Abnormal Content-Length Values After Transfer-Encoding
    description: Detects when Tinyproxy sets a negative Content-Length value after processing a Transfer-Encoding header, indicating a potential exploit of CVE-2026-31842.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tinyproxy, a lightweight HTTP/HTTPS proxy daemon, is susceptible to HTTP request parsing desynchronization due to an issue in how it handles the `Transfer-Encoding` header. Specifically, versions up to and including 1.11.3 perform a case-sensitive comparison of the `Transfer-Encoding` header value against "chunked". This deviates from RFC 7230, which mandates case-insensitive handling of transfer-coding names. An unauthenticated remote attacker can exploit this vulnerability (CVE-2026-31842) by sending a specially crafted HTTP request with a modified `Transfer-Encoding` header (e.g., `Transfer-Encoding: Chunked`). This causes Tinyproxy to misinterpret the request, potentially leading to denial-of-service (DoS) conditions due to backend worker exhaustion or bypassing security controls when Tinyproxy is used for request inspection and filtering. The vulnerability was published on 2026-04-07 and impacts deployments where Tinyproxy is used as a forward or reverse proxy.

## Attack Chain

1.  The attacker sends a crafted HTTP request to the Tinyproxy server. The request includes a `Transfer-Encoding` header with a case variation of "chunked", such as "Chunked".
2.  Tinyproxy's `is_chunked_transfer()` function in `src/reqs.c` uses `strcmp()` to compare the header value against "chunked".
3.  Due to the case-sensitive comparison, the header value does not match "chunked", and Tinyproxy misinterprets the request as not using chunked transfer encoding.
4.  Tinyproxy sets `content_length.client` to -1 and skips the `pull_client_data_chunked()` function.
5.  Tinyproxy forwards the request headers upstream to the backend server.
6.  Tinyproxy transitions into `relay_connection()`, initiating raw TCP forwarding of data. However, unread body data remains buffered on the Tinyproxy server.
7.  The backend server, expecting a chunked request body, waits indefinitely for the remaining data, leading to a hung connection.
8.  Repeated exploitation exhausts backend server resources, resulting in application-level denial of service. In scenarios involving request inspection, uninspected data is forwarded, bypassing security controls.

## Impact

Successful exploitation of CVE-2026-31842 can lead to application-level denial of service due to backend worker exhaustion. RFC-compliant backend servers, such as Node.js or Nginx, will indefinitely wait for chunked body data, consuming resources. In deployments where Tinyproxy is used for security enforcement (request body inspection, filtering), the vulnerability allows attackers to bypass these controls by sending uninspected data to the backend server. The specific number of affected installations is unknown, but all deployments of Tinyproxy versions 1.11.3 and earlier are vulnerable.

## Recommendation

*   Upgrade Tinyproxy to a patched version that addresses the case-sensitive comparison of the `Transfer-Encoding` header (check the vendor website for the latest version).
*   Deploy the Sigma rule "Detect Case-Variant Transfer-Encoding Header" to detect exploitation attempts in real-time by monitoring web server logs for requests with malformed `Transfer-Encoding` headers.
*   Monitor Tinyproxy's logs for unusual connection patterns or error messages that may indicate exploitation attempts.
*   Implement web application firewall (WAF) rules to normalize or reject requests with non-standard `Transfer-Encoding` headers, mitigating the vulnerability at the perimeter.
