---
title: Cross-Site Request Forgery Vulnerability in djust SSE Transport
slug: 2026-09-djust-csrf
description: The djust library before version 1.0.7 is vulnerable to CSRF via its SSE transport, allowing cross-origin requests to execute state-changing event handlers as an authenticated victim.
date: "2026-09-16T19:07:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:djust_project:djust:*:*:*:*:*:*:*:*
tags:
  - web-application-security
  - csrf
  - sse
  - vulnerability
products:
  - djust (< 1.0.7)
cves:
  - id: CVE-2026-61593
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-pg97-jvmf-qfvc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61593
rules:
  - title: Detects CVE-2026-61593 Exploitation - Cross-Origin SSE Request
    description: Detects potential CSRF exploitation attempts against djust SSE endpoints by monitoring for requests with cross-origin headers or suspicious simple-request content types.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade djust to version 1.0.7 or later
      owner: IT Operations
      due: 24h
      evidence: Fixed in djust 1.0.7
  mitigation_plan:
    - priority: immediate
      action: Configure proxy to enforce strict Origin header validation
      owner: IT Operations
      addresses: CVE-2026-61593
      evidence: Front it with a proxy that enforces an Origin allowlist
---

The djust library, prior to version 1.0.7, contains a high-severity Cross-Site Request Forgery (CSRF) vulnerability (CVE-2026-61593) affecting its Server-Sent-Events (SSE) transport implementation. The vulnerability stems from a lack of Origin header validation on SSE endpoints and the use of CSRF-exempted POST endpoints. Because the library allows client-chosen session identifiers and accepts requests with a 'text/plain' content type, an attacker can bypass CORS preflight checks to perform 'simple requests' from a malicious cross-origin page. This enables an attacker to force an authenticated victim's browser to establish an SSE session, mount a LiveView, and execute state-changing event handlers on behalf of the victim. Defenders should prioritize patching to version 1.0.7, which introduces strict Origin validation against 'ALLOWED_HOSTS' and mandates 'application/json' content-type checks.

## Impact

Successful exploitation allows an unauthorized remote attacker to perform state-changing actions within the application context of an authenticated victim. This can lead to unauthorized data modification, account takeover, or the execution of privileged administrative actions. The vulnerability affects all applications using djust prior to version 1.0.7.

## Recommendation

- Upgrade the djust package to version 1.0.7 or later to implement required Origin validation and content-type enforcement.
- If immediate patching is not possible, disable the SSE transport entirely or implement a reverse proxy layer capable of enforcing strict Origin header allowlisting for all traffic directed to the SSE endpoints.
- Monitor web server access logs for anomalous cross-origin POST requests or SSE stream requests originating from unexpected domains.
