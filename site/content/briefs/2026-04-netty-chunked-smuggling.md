---
title: Netty HTTP Request Smuggling via Chunked Extension Quoted-String Parsing
slug: 2026-04-netty-chunked-smuggling
description: Netty incorrectly parses quoted strings in HTTP/1.1 chunked transfer encoding extension values, enabling request smuggling attacks by terminating chunk header parsing at \r\n inside quoted strings instead of rejecting the malformed request.
date: "2026-03-26T18:51:27Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - netty
  - request-smuggling
  - http
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-pwqr-wmgm-9rr8
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
  - title: Detect Netty Chunked Transfer Encoding Request Smuggling
    description: Detects HTTP requests with chunked transfer encoding and chunk extensions containing quoted strings with embedded carriage returns and line feeds, indicative of request smuggling attempts targeting Netty.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious HTTP Request Line After Chunked Data
    description: Detects a second HTTP request line immediately following chunked data, indicating potential request smuggling.
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

A vulnerability exists in Netty's HTTP/1.1 chunked transfer encoding extension parsing, specifically in how it handles quoted strings. This flaw, discovered during research into "Funky Chunks" HTTP request smuggling techniques, stems from Netty terminating chunk header parsing at `\r\n` inside quoted strings, instead of rejecting the request as malformed. This behavior deviates from RFC 9110, which mandates that CR (`%x0D`) and LF (`%x0A`) bytes are not permitted inside chunk extensions. This parsing differential allows attackers to smuggle HTTP requests. Versions affected include netty-codec-http < 4.1.132.Final and netty-codec-http versions >= 4.2.0.Alpha1 and < 4.2.10.Final. This matters for defenders because successful exploitation can lead to severe consequences, including cache poisoning and session hijacking.

## Attack Chain

1. The attacker sends a crafted HTTP request with chunked transfer encoding.
2. The request includes a chunk extension containing a quoted string with embedded `\r\n` characters. For example: `1;a="\r\n`.
3. Netty's HTTP parser incorrectly terminates the chunk header parsing at the embedded `\r\n`.
4. The remaining portion of the intended chunk extension and the subsequent chunk data are interpreted as the beginning of a new HTTP request.
5. The attacker injects a smuggled HTTP request, such as `GET /smuggled HTTP/1.1`.
6. The vulnerable server processes both the initial and smuggled requests on the same connection.
7. The smuggled request is executed, potentially bypassing security controls or accessing sensitive data.
8. The server returns responses for both requests, potentially leading to cache poisoning or other malicious outcomes.

## Impact

Successful exploitation of this vulnerability can lead to request smuggling, allowing attackers to inject arbitrary HTTP requests into a connection. This can result in cache poisoning, where smuggled responses may poison shared caches. Additionally, access control bypasses can occur, where smuggled requests circumvent frontend security controls. Session hijacking is also possible, where smuggled requests may intercept responses intended for other users. The impact is significant as it can compromise the confidentiality, integrity, and availability of web applications and services using vulnerable Netty versions.

## Recommendation

*   Upgrade to Netty version 4.1.132.Final or 4.2.10.Final or later to remediate CVE-2026-33870.
*   Deploy the Sigma rule "Detect Netty Chunked Transfer Encoding Request Smuggling" to identify potentially malicious requests exploiting this vulnerability.
*   Inspect web server logs for HTTP requests with chunked transfer encoding and chunk extensions containing quoted strings with embedded carriage returns and line feeds (`\r\n`) to identify exploitation attempts.
*   Monitor network traffic for connections to 127.0.0.1 on port 8080 which is used in the proof of concept for request smuggling.
