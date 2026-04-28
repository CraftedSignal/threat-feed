---
title: Eclipse Jetty HTTP/1.1 Request Smuggling via Chunk Extensions (CVE-2026-2332)
slug: 2026-04-jetty-smuggling
description: Eclipse Jetty's HTTP/1.1 parser is vulnerable to request smuggling due to improper handling of chunk extensions, allowing attackers to inject malicious requests.
date: "2026-04-14T12:16:21Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - request-smuggling
  - jetty
  - cve-2026-2332
  - funky-chunks
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-2332
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2332
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
  - title: Detect Jetty Request Smuggling via Malformed Chunk Extensions
    description: Detects request smuggling attempts in Jetty by identifying HTTP requests with chunked transfer encoding and malformed chunk extensions containing unclosed quotes and newlines.
    platform: sigma
    severity: critical
    data_sources:
      - webserver
      - linux
  - title: Detect Jetty Request Smuggling via Malformed Chunk Length
    description: Detects request smuggling attempts in Jetty by identifying HTTP requests with chunked transfer encoding and malformed chunk length.
    platform: sigma
    severity: high
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Eclipse Jetty is susceptible to request smuggling attacks (CVE-2026-2332) due to a flaw in its HTTP/1.1 parser. The vulnerability stems from the parser's failure to properly handle chunk extensions within chunked transfer encoding. Specifically, Jetty incorrectly terminates chunk extension parsing at a carriage return and line feed (\r\n) sequence inside quoted strings, rather than treating it as an error. This behavior allows attackers to inject arbitrary HTTP requests by crafting malformed chunk extensions, potentially bypassing security controls and gaining unauthorized access to resources. The "funky chunks" research highlights similar attack vectors, underscoring the severity of this vulnerability. This issue impacts all Jetty users and requires immediate attention from security teams.

## Attack Chain

1.  Attacker sends an HTTP POST request to the targeted Jetty server.
2.  The request includes the `Transfer-Encoding: chunked` header to enable chunked transfer encoding.
3.  The attacker crafts a malformed chunk extension that includes an unclosed quoted string containing a newline (`\r\n`). Example: `1;ext="val\r\nX`.
4.  Jetty's HTTP/1.1 parser incorrectly terminates the chunk extension parsing at the newline within the quoted string.
5.  The parser then interprets the subsequent data (e.g., `0\r\n\r\nGET /smuggled HTTP/1.1\r\n...`) as a new, smuggled HTTP request.
6.  Jetty processes the smuggled request as if it were a legitimate request from the client.
7.  The smuggled request can be used to access restricted resources, modify data, or perform other malicious actions.
8.  The attacker gains unauthorized access or control over the application.

## Impact

Successful exploitation of this request smuggling vulnerability (CVE-2026-2332) can lead to severe consequences, including unauthorized access to sensitive data, modification of application functionality, and complete compromise of the web application. The number of potential victims is extensive, as Jetty is a widely used web server and servlet container. Sectors at risk include any organization that uses Jetty, such as finance, healthcare, and e-commerce. The CVSS v3.1 base score for this vulnerability is 7.4, indicating a high level of severity.

## Recommendation

*   Apply the official patch or upgrade to a version of Jetty that addresses CVE-2026-2332 as soon as possible.
*   Deploy the Sigma rule "Detect Jetty Request Smuggling via Malformed Chunk Extensions" to identify and alert on exploitation attempts (see rules).
*   Inspect web server access logs for unusual patterns in chunked requests, particularly those with long or malformed chunk extensions (see "webserver" log source).
*   Block access to the malicious URLs `https://w4ke.info/2025/06/18/funky-chunks.html` and `https://w4ke.info/2025/10/29/funky-chunks-2.html` at your web proxy or firewall as these are related to the attack techniques (see IOCs).
