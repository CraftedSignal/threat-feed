---
title: Netty HTTP Request Smuggling via Chunked Extension Quoted-String Parsing
slug: 2026-04-netty-chunked-smuggling
description: Netty incorrectly parses quoted strings in HTTP/1.1 chunked transfer encoding extension values, enabling request smuggling attacks by terminating chunk header parsing at \r\n inside quoted strings instead of rejecting the malformed request.
date: "2026-03-26T18:51:27Z"
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

A vulnerability exists in Netty's HTTP/1.1 chunked transfer encoding extension parsing, specifically in how it handles quoted strings. This flaw, discovered during research into "Funky Chunks" HTTP request smuggling techniques, stems from Netty terminating chunk header parsing at `\r\n` inside quoted strings, instead of rejecting the request as malformed. This behavior deviates from RFC 9110, which mandates that CR (`%x0D`) and LF (`%x0A`) bytes are not permitted inside chunk extensions. This…
