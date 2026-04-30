---
title: Jetty HTTP Request Smuggling via Chunked Extension Quoted-String Parsing
slug: 2026-04-jetty-request-smuggling
description: Jetty is vulnerable to HTTP request smuggling due to improper parsing of quoted strings in HTTP/1.1 chunked transfer encoding extension values, potentially allowing attackers to inject arbitrary HTTP requests, poison caches, and bypass security controls.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - request-smuggling
  - jetty
  - CVE-2026-2332
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-2332
    cvss: 7.4
references:
  - https://github.com/advisories/GHSA-355h-qmc2-wpwf
  - https://w4ke.info/2025/06/18/funky-chunks.html
  - https://w4ke.info/2025/10/29/funky-chunks-2.html
iocs:
  - type: url
    value: https://w4ke.info/2025/06/18/funky-chunks.html
  - type: url
    value: https://w4ke.info/2025/10/29/funky-chunks-2.html
ioc_counts:
  url: 2
rules:
  - title: Detect Jetty HTTP Request Smuggling
    description: Detects HTTP requests with chunked transfer encoding where the chunk extension contains a quoted string with a CRLF sequence, indicating a potential request smuggling attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Jetty HTTP Request Smuggling - Alternative
    description: Detects HTTP requests with chunked transfer encoding where the chunk extension contains a quoted string with a CRLF sequence, based on request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Jetty versions 9.4.0 through 12.1.6 are vulnerable to HTTP request smuggling due to incorrect parsing of quoted strings in HTTP/1.1 chunked transfer encoding extensions. This flaw stems from Jetty's premature termination of chunk header parsing upon encountering a carriage return and line feed (CRLF) sequence within a quoted string, violating RFC 9112 specifications. An attacker can exploit this vulnerability to inject malicious HTTP requests into the application's request stream, potentially bypassing security controls, poisoning caches, and even hijacking user sessions. This issue, identified as CVE-2026-2332, poses a significant risk to applications using affected Jetty versions. The vulnerability was discovered during research into "Funky Chunks" HTTP request smuggling techniques and highlights the importance of rigorous adherence to RFC specifications in HTTP server implementations.

## Attack Chain

1. The attacker sends a crafted HTTP POST request with chunked transfer encoding to a vulnerable Jetty server.
2. The chunk header includes a quoted string within the chunk extension, containing a CRLF sequence. For example: `Chunk: 1;a="\r\n`.
3. Jetty incorrectly parses the chunk header, terminating parsing at the CRLF within the quoted string.
4. The remaining portion of the intended chunk extension and subsequent data are interpreted as the beginning of a new HTTP request.
5. The attacker injects a malicious HTTP GET request intended to be smuggled, such as `GET /smuggled HTTP/1.1`.
6. The smuggled request is processed by the server, potentially bypassing frontend security checks.
7. The server responds to the smuggled request.
8. The attacker may use the smuggled request to poison the cache, bypass access controls, or potentially hijack user sessions by intercepting sensitive data in the smuggled response.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary HTTP requests into the application's request stream. This can lead to several severe consequences, including: cache poisoning, where malicious content is served to legitimate users; access control bypass, enabling unauthorized access to sensitive resources; and session hijacking, allowing attackers to impersonate other users. The vulnerability impacts Jetty versions 9.4.0 through 12.1.6. The number of affected installations is currently unknown. The primary target is any web application utilizing a vulnerable version of Jetty.

## Recommendation

*   Upgrade to a patched version of Jetty that addresses CVE-2026-2332.
*   Deploy the Sigma rule `Detect Jetty HTTP Request Smuggling` to your SIEM and tune for your environment to detect exploitation attempts.
*   Inspect web server logs for malformed chunk headers containing CRLF sequences within quoted strings, as this indicates a potential exploitation attempt.
