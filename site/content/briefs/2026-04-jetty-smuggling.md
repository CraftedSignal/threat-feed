---
title: Eclipse Jetty HTTP/1.1 Request Smuggling via Chunk Extensions (CVE-2026-2332)
slug: 2026-04-jetty-smuggling
description: Eclipse Jetty's HTTP/1.1 parser is vulnerable to request smuggling due to improper handling of chunk extensions, allowing attackers to inject malicious requests.
date: "2026-04-14T12:16:21Z"
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

Eclipse Jetty is susceptible to request smuggling attacks (CVE-2026-2332) due to a flaw in its HTTP/1.1 parser. The vulnerability stems from the parser's failure to properly handle chunk extensions within chunked transfer encoding. Specifically, Jetty incorrectly terminates chunk extension parsing at a carriage return and line feed (\r\n) sequence inside quoted strings, rather than treating it as an error. This behavior allows attackers to inject arbitrary HTTP requests by crafting malformed…
