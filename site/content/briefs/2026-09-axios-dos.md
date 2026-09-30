---
title: Denial of Service in Axios via Unhandled HTTP/2 Session Errors
slug: 2026-09-axios-dos
description: Axios versions prior to 1.20.0 are vulnerable to a denial-of-service condition where unhandled 'error' events on ClientHttp2Session objects cause the parent Node.js process to terminate.
date: "2026-09-30T16:28:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:axios:axios:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - nodejs
  - software-vulnerability
products:
  - axios (>= 1.13.0, < 1.20.0)
cves:
  - id: CVE-2026-101901
    epss: 0.00384
references:
  - https://github.com/advisories/GHSA-542g-h47m-68v8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101901
action_plan:
  priority: immediate_escalation
  owners:
    - Development Teams
  immediate_actions:
    - action: Upgrade Axios to version 1.20.0 or later
      owner: Development Teams
      due: 24h
      evidence: Source advisory confirms patch in 1.20.0
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP/2 support in Axios configurations for untrusted destinations
      owner: Development Teams
      addresses: CVE-2026-101901
      evidence: Workaround documented in GHSA advisory
---

Axios versions 1.13.0 through 1.19.x contain a vulnerability in the handling of Node.js HTTP/2 sessions. When using the HTTP/2 adapter, Axios establishes connections using the Node.js 'http2' module. The internal session management logic fails to attach an 'error' event listener to the initialized 'ClientHttp2Session' objects. If a network error, connection failure, or server-side rejection occurs during session initialization, the Node.js runtime treats the resulting error as an unhandled EventEmitter exception. This behavior bypasses standard Axios Promise rejection patterns, leading to an immediate termination of the application process. 

This issue is specific to configurations where 'httpVersion' is set to 2. Applications using default HTTP/1.1 settings or those utilizing browser-based XHR/fetch adapters are not affected. Defenders should prioritize auditing applications that interface with user-supplied or untrusted URLs via HTTP/2, as these provide the most direct vector for triggering the unhandled exception and achieving a denial-of-service state.

## Attack Chain

1. The application initializes an Axios instance with `httpVersion: 2` configured.
2. The application triggers an outgoing HTTP request to a destination controlled or influenced by an attacker.
3. Axios calls `http2.connect()` to initialize a new session with the target authority.
4. The remote target (or network intermediary) forces a connection error (e.g., reset, connection refused, or TLS failure).
5. The underlying `ClientHttp2Session` object emits an 'error' event to the process.
6. Because no error listener is attached within the Axios session manager, the Node.js process treats the error as an uncaught exception.
7. The application process exits abruptly, resulting in a denial-of-service for all concurrent users.

## Impact

Successful exploitation results in an immediate denial-of-service for the vulnerable Node.js process. This can impact service availability for any users of the application. The vulnerability is highly disruptive in high-traffic microservices or web applications that rely on Axios for backend-to-backend communication, as a single malicious or malformed request can crash the entire service instance.

## Recommendation

1. Upgrade to Axios version 1.20.0 or later immediately to incorporate the necessary 'error' event handling logic.
2. For environments where immediate patching is not feasible, disable the use of the HTTP/2 adapter in Axios for any request destinations that involve user input or untrusted origins.
3. Review application configurations to ensure 'http2Options' are not derived from raw, unvalidated user-controlled input, as this increases the likelihood of triggering edge-case connection failures.
