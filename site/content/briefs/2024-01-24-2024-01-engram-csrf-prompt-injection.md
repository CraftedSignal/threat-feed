---
title: engramx vulnerable to CSRF enabling graph exfiltration and prompt injection
slug: 2024-01-engram-csrf-prompt-injection
description: The engramx HTTP server, enabled by default and binding to 127.0.0.1:7337, is vulnerable to CSRF and prompt injection attacks, allowing a malicious website to exfiltrate the local knowledge graph and inject persistent prompt-injection payloads.
date: "2024-01-24T12:00:00Z"
severities:
  - high
tags:
  - csrf
  - prompt-injection
  - engramx
products:
  - engramx
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://github.com/advisories/GHSA-2r2p-4cgf-hv7h
rules:
  - title: Detect engramx API access without authentication
    description: Detects access to the engramx API without proper authentication, indicating a potential CSRF attack.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.001
    data_sources:
      - webserver
      - linux
  - title: 'Detect POST requests to /learn without Content-Type: application/json'
    description: Detects POST requests to the /learn endpoint without the expected Content-Type header, indicating a potential CSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `engramx` HTTP server, which is enabled by default and listens on `127.0.0.1:7337`, is vulnerable to Cross-Site Request Forgery (CSRF) and prompt injection attacks in versions prior to 2.0.2. This vulnerability stems from a combination of a wildcard CORS policy (`Access-Control-Allow-Origin: *`) and the absence of authentication by default. An attacker could exploit this by enticing a developer to visit a malicious web page, leading to the exfiltration of sensitive data from the local…
