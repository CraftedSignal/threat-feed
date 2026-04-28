---
title: BigSweetPotatoStudio HyperChat AI Proxy Middleware Server-Side Request Forgery
slug: 2024-01-23-hyperchat-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in BigSweetPotatoStudio HyperChat up to version 2.0.0-alpha.63, allowing a remote attacker to manipulate the 'baseurl' argument in the 'fetch' function of the AI Proxy Middleware component to make arbitrary HTTP requests.
date: "2024-01-23T12:00:00Z"
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - webserver
vendors:
  - BigSweetPotatoStudio
products:
  - HyperChat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7223
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7223
rules:
  - title: HyperChat SSRF Attempt
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in BigSweetPotatoStudio HyperChat by monitoring HTTP requests containing suspicious baseurl parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: HyperChat SSRF Attempt External
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in BigSweetPotatoStudio HyperChat by monitoring HTTP requests containing suspicious external baseurl parameters.
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

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-7223, affects BigSweetPotatoStudio HyperChat up to version 2.0.0-alpha.63. The vulnerability resides in the 'fetch' function within the AI Proxy Middleware located at `packages/core/src/http/aiProxyMiddleware.mts`. By manipulating the `baseurl` argument, a remote attacker can force the server to make arbitrary HTTP requests to internal or external resources. This issue allows attackers to potentially access sensitive…
