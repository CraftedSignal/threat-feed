---
title: Authentication Bypass in 9router Public LLM API
slug: 2026-09-9router-auth-bypass
description: 9router is vulnerable to an authentication bypass via a spoofable X-9r-Real-Ip HTTP header, allowing unauthenticated attackers to access LLM API endpoints.
date: "2026-09-22T19:53:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:9router:9router:*:*:*:*:*:*:*:*
tags:
  - web-application
  - auth-bypass
vendors:
  - 9router
products:
  - 9router-app (<= 0.5.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The authorization layer makes a security decision based on a client-controllable HTTP header.
    confidence_band: high
cves:
  - id: CVE-2026-56681
    cvss: 7.3
references:
  - https://github.com/advisories/GHSA-5mj8-gf6m-fhw8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56681
rules:
  - title: Detects CVE-2026-56681 Exploitation - 9router Auth Bypass
    description: Detects unauthorized access to 9router API endpoints via spoofed X-9r-Real-Ip header
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block X-9r-Real-Ip header from public traffic at WAF/edge
      owner: SOC
      due: 24h
      evidence: 'Source states: do not trust X-9r-Real-Ip when received directly from clients.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade 9router to latest version or ensure custom-server.js usage
      owner: IT Operations
      addresses: CVE-2026-56681
      evidence: Source remediation section
---

9router versions 0.5.4 and earlier contain a critical authentication bypass vulnerability (CVE-2026-56681) within the public LLM API layer. The application improperly trusts the user-supplied 'X-9r-Real-Ip' HTTP header to determine if a request originates from the local host (localhost). Under default deployment modes where the intended 'custom-server.js' security wrapper is absent, the application fails to strip or sanitize this header from inbound client traffic. A remote, unauthenticated attacker can inject 'X-9r-Real-Ip: 127.0.0.1' into HTTP requests to 'isLocalRequest()', which then instructs 'canAccessPublicLlmApi()' to waive mandatory API key validation. This vulnerability permits unauthorized access to the LLM provider resources configured by the instance owner, potentially leading to significant financial loss and account abuse.

## Attack Chain

1. Attacker identifies a target 9router instance exposed via port 80/443 without the custom-server.js wrapper.
2. Attacker crafts an HTTP GET request to a protected endpoint, such as '/api/v1/models'.
3. Attacker adds the header 'X-9r-Real-Ip: 127.0.0.1' to the HTTP request.
4. The 9router application receives the request and executes 'isLocalRequest()' in 'src/dashboardGuard.js'.
5. The application erroneously reads the spoofed header value and returns 'true' for local origin validation.
6. The logic proceeds to 'canAccessPublicLlmApi()', which identifies the request as 'local' and skips API key authentication.
7. The application returns '200 OK', granting the attacker access to the model catalog and provider proxy.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass API key enforcement on the public LLM API. Impact includes the unauthorized consumption of the instance owner's paid LLM API credits, unauthorized access to configured provider infrastructure, enumeration of private model configurations, and potential abuse of upstream LLM provider accounts.

## Recommendation

- Upgrade 9router to a version that implements secure transport-level source validation, or ensure deployment uses the required 'custom-server.js' wrapper to sanitize headers.
- Implement a web application firewall (WAF) rule to block or strip the 'X-9r-Real-Ip' header from any incoming public traffic.
- Deploy the Sigma rule below to detect attempts to access the '/api/v1/' path with the malicious header present in web server logs.
- Audit current environment configurations to ensure 'custom-server.js' is correctly protecting all public-facing instances.
