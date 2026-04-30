---
title: Moxi Blog v2 <= 5.2 Server-Side Request Forgery Vulnerability
slug: 2026-04-mogu-blog-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in moxi624 Mogu Blog v2 up to version 5.2, specifically affecting the `LocalFileServiceImpl.uploadPictureByUrl` function, allowing remote attackers to potentially interact with internal resources.
date: "2026-04-20T10:16:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - SSRF
  - Mogu Blog
  - CVE-2026-6625
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6625
rules:
  - title: Detect SSRF Attempts via Internal IP in Mogu Blog URL Parameter
    description: Detects potential SSRF attempts in Mogu Blog by identifying requests where the URL parameter (likely used by uploadPictureByUrl) contains internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from Mogu Blog Server to Private IP Ranges
    description: Detects network connections originating from the Mogu Blog server to private IP address ranges, which could indicate SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Moxi Blog v2, a blogging platform, is vulnerable to a server-side request forgery (SSRF) vulnerability (CVE-2026-6625) in versions up to 5.2. The vulnerability resides within the `LocalFileServiceImpl.uploadPictureByUrl` function of the Picture Storage Service component. This flaw allows a remote attacker to potentially force the server to make HTTP requests to arbitrary domains, including internal services, potentially exposing sensitive information or allowing unauthorized actions. The vulnerability has been publicly disclosed, making it crucial to address this issue to prevent potential exploitation. The vendor has been notified but has not responded.

## Attack Chain

1.  The attacker identifies a Mogu Blog v2 instance running a vulnerable version (<= 5.2).
2.  The attacker crafts a malicious HTTP request targeting the `uploadPictureByUrl` function.
3.  Within the crafted request, the attacker provides a URL pointing to an internal resource or an external server controlled by the attacker.
4.  The Mogu Blog server processes the request and attempts to retrieve the resource specified in the URL via an HTTP GET request.
5.  If the targeted URL points to an internal service, the server may inadvertently expose sensitive information (e.g., internal API keys, service configurations).
6.  If the targeted URL points to an external server controlled by the attacker, the server may leak information about itself (e.g., internal IP address, software versions).
7.  The attacker analyzes the response from the server to gather sensitive information or identify further attack vectors.

## Impact

Successful exploitation of this SSRF vulnerability could allow an attacker to scan internal networks, access internal services not exposed to the public internet, potentially read sensitive data, or leverage the server as a proxy to attack other systems. This can lead to information disclosure, unauthorized access to internal resources, and further compromise of the Mogu Blog infrastructure. The number of affected installations is unknown, but all instances of Mogu Blog v2 up to 5.2 are potentially vulnerable.

## Recommendation

*   Inspect web server logs for requests containing URLs to internal IP addresses (e.g. 127.0.0.1, 192.168.x.x, 10.x.x.x) in the `cs-uri-query` field using a webserver log rule.
*   Monitor network connections originating from the Mogu Blog server to unusual or internal destinations, using a `network_connection` Sigma rule.
*   Implement input validation and sanitization for the `uploadPictureByUrl` function to prevent the server from making requests to untrusted URLs.
*   Apply any available patches or updates from the vendor to address CVE-2026-6625 (though no vendor response was noted).
