---
title: i18next-http-middleware Prototype Pollution and Path Traversal Vulnerability
slug: 2024-01-i18next-http-middleware-vuln
description: Versions of i18next-http-middleware before 3.9.3 are vulnerable to prototype pollution, path traversal, and server-side request forgery (SSRF) due to improper validation of user-controlled language and namespace parameters, potentially leading to denial of service or remote code execution.
date: "2024-01-26T12:00:00Z"
severities:
  - high
tags:
  - prototype-pollution
  - path-traversal
  - ssrf
  - denial-of-service
  - i18next
vendors:
  - npm
products:
  - i18next-http-middleware
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5fgg-jcpf-8jjw
rules:
  - title: Detect Prototype Pollution Attempt via i18next HTTP Middleware
    description: Detects attempts to exploit the prototype pollution vulnerability in i18next-http-middleware by checking for `__proto__`, `constructor`, or `prototype` in the `lng` or `ns` parameters.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal Attempt via i18next HTTP Middleware
    description: Detects attempts to exploit path traversal vulnerability in i18next-http-middleware by checking for directory traversal sequences in the `lng` or `ns` parameters.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

i18next-http-middleware versions prior to 3.9.3 are susceptible to prototype pollution, path traversal, and SSRF attacks. The vulnerability stems from the insufficient validation of the `lng` (language) and `ns` (namespace) parameters passed via HTTP requests to the `getResourcesHandler` and the `missingKeyHandler`. These handlers, intended to serve localization resources, expose attack surface because they process user-controlled input without proper sanitization. This allows attackers to…
