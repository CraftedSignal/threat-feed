---
title: Fastify Proxy Header Stripping Vulnerability
slug: 2026-04-fastify-header-strip
description: The `@fastify/reply-from` and `@fastify/http-proxy` libraries process the client's `Connection` header after adding headers, allowing attackers to strip proxy-added headers via the `Connection` header, leading to potential bypass of security controls.
date: "2026-04-16T01:02:59Z"
severities:
  - critical
tags:
  - fastify
  - header stripping
  - proxy vulnerability
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-gwhp-pf74-vj37
rules:
  - title: Detect Fastify Proxy Header Stripping Attempt
    description: Detects requests with a 'Connection' header attempting to strip common proxy-added headers.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: 'Detect Fastify Proxy Header Stripping - Connection: close'
    description: Detects requests with a 'Connection' header set to 'close', which, while legitimate, could be used in conjunction with other header manipulation techniques.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `@fastify/reply-from` and `@fastify/http-proxy` libraries are vulnerable to a header stripping attack. This vulnerability stems from the incorrect processing order of the `Connection` header. The client's `Connection` header is processed *after* the proxy has added custom headers via the `rewriteRequestHeaders` function. This allows an attacker to retroactively remove headers added by the proxy by simply listing them in the `Connection` header. This affects any application leveraging these…
