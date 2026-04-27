---
title: Jetty HTTP Request Smuggling via Chunked Extension Quoted-String Parsing
slug: 2026-04-jetty-request-smuggling
description: Jetty is vulnerable to HTTP request smuggling due to improper parsing of quoted strings in HTTP/1.1 chunked transfer encoding extension values, potentially allowing attackers to inject arbitrary HTTP requests, poison caches, and bypass security controls.
date: "2026-04-15T12:00:00Z"
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

Jetty versions 9.4.0 through 12.1.6 are vulnerable to HTTP request smuggling due to incorrect parsing of quoted strings in HTTP/1.1 chunked transfer encoding extensions. This flaw stems from Jetty's premature termination of chunk header parsing upon encountering a carriage return and line feed (CRLF) sequence within a quoted string, violating RFC 9112 specifications. An attacker can exploit this vulnerability to inject malicious HTTP requests into the application's request stream, potentially…
