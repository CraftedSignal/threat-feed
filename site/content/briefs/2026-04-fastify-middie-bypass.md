---
title: '@fastify/middie Middleware Bypass Vulnerability (CVE-2026-33804)'
slug: 2026-04-fastify-middie-bypass
description: A middleware bypass vulnerability (CVE-2026-33804) exists in @fastify/middie versions 9.3.1 and earlier when the deprecated Fastify ignoreDuplicateSlashes option is enabled, potentially allowing unauthorized access.
date: "2026-04-16T15:17:34Z"
severities:
  - high
tags:
  - fastify
  - middie
  - middleware
  - bypass
  - cve-2026-33804
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
cves:
  - id: CVE-2026-33804
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33804
rules:
  - title: Detect Fastify Middie Bypass Attempt
    description: Detects potential attempts to bypass @fastify/middie middleware by exploiting CVE-2026-33804 using duplicate slashes in the request URI.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect Fastify Middie Bypass Attempt - HTTP Method
    description: Detects potential attempts to bypass @fastify/middie middleware by exploiting CVE-2026-33804 using duplicate slashes in the request URI and specific HTTP Methods.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

@fastify/middie, a Fastify middleware engine, is vulnerable to a significant security bypass. Specifically, versions 9.3.1 and earlier are susceptible when the deprecated Fastify `ignoreDuplicateSlashes` option is enabled. This vulnerability, identified as CVE-2026-33804, arises because the middleware's path matching logic fails to account for the duplicate slash normalization performed by Fastify's router. Consequently, crafted HTTP requests containing duplicate slashes can circumvent…
