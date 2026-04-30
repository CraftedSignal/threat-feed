---
title: engramx vulnerable to CSRF enabling graph exfiltration and prompt injection
slug: 2024-01-engram-csrf-prompt-injection
description: The engramx HTTP server, enabled by default and binding to 127.0.0.1:7337, is vulnerable to CSRF and prompt injection attacks, allowing a malicious website to exfiltrate the local knowledge graph and inject persistent prompt-injection payloads.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
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

The `engramx` HTTP server, which is enabled by default and listens on `127.0.0.1:7337`, is vulnerable to Cross-Site Request Forgery (CSRF) and prompt injection attacks in versions prior to 2.0.2. This vulnerability stems from a combination of a wildcard CORS policy (`Access-Control-Allow-Origin: *`) and the absence of authentication by default. An attacker could exploit this by enticing a developer to visit a malicious web page, leading to the exfiltration of sensitive data from the local knowledge graph and the injection of malicious payloads. The vulnerability was discovered and responsibly disclosed by @gabiudrescu in engram issue #7. Defenders should prioritize upgrading to version 2.0.2 or implementing the provided workarounds to mitigate the risk of unauthorized access and persistent compromise.

## Attack Chain

1. A developer installs a vulnerable version of `engramx` (>= 1.0.0, < 2.0.2) and the HTTP server starts by default.
2. The server binds to `127.0.0.1:7337` and serves requests without requiring authentication unless `ENGRAM_API_TOKEN` is explicitly set.
3. A developer visits a malicious website in their browser.
4. The malicious website crafts a cross-origin request to `127.0.0.1:7337` due to the `Access-Control-Allow-Origin: *` header.
5. A `GET` request to `/query` or `/stats` is sent, exfiltrating the local knowledge graph, including function names, file layout, and recorded decisions/mistakes.
6. A `POST` request to `/learn` is sent with a crafted prompt-injection payload, exploiting the lack of `Content-Type: application/json` enforcement.
7. The injected payload is written as `mistake`/`decision` nodes in the knowledge graph.
8. The user's AI coding agent is persistently reminded of the injected payload on every future session and file edit, leading to compromised code generation and execution.

## Impact

Successful exploitation of this vulnerability could lead to the compromise of sensitive developer data, including internal function names, file layouts, and coding decisions, allowing attackers to gain insights into the target's projects. Furthermore, the injection of persistent prompt-injection payloads can lead to the ongoing corruption of the user's AI coding agent, potentially causing the generation of flawed or malicious code. While the exact number of affected users is unknown, any developer using a vulnerable version of `engramx` is susceptible to this attack.

## Recommendation

*   Upgrade to `engramx@2.0.2` or later to apply the remediation measures outlined in the advisory.
*   If upgrading is not immediately feasible, do **not** run `engram server` or `engram ui` as a workaround.
*   If `engram server` must be run, set `ENGRAM_API_TOKEN` to a long random value and terminate the server before browsing the web (as noted in the advisory).
*   Deploy the Sigma rule "Detect engramx API access without authentication" to identify potentially unauthorized access attempts to the engramx API.
*   Monitor network connections to port 7337 on localhost, filtering for unexpected processes initiating connections.
