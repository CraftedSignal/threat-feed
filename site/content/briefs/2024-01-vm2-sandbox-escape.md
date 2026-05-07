---
title: vm2 Sandbox Escape via Promise Constructor Unhandled Rejection
slug: 2024-01-vm2-sandbox-escape
description: A sandbox escape vulnerability exists in vm2 versions 3.10.5 and earlier that allows sandboxed code to crash the host Node.js process via a Promise constructor that triggers an unhandled rejection, leading to a denial-of-service condition.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vm2
  - sandbox-escape
  - denial-of-service
  - nodejs
vendors:
  - npm
products:
  - vm2 (<= 3.10.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-22709
    cvss: 9.8
    epss: 0.00046
references:
  - https://github.com/advisories/GHSA-hw58-p9xv-2mjh
rules:
  - title: Detect vm2 Sandbox Escape Attempt via Symbol Error Name
    description: Detects attempts to exploit the vm2 sandbox escape vulnerability by identifying code that sets Error.name to a Symbol within a vm2 process.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect vm2 Sandbox Escape Attempt via Unhandled Rejection
    description: 'Detects attempts to exploit the vm2 sandbox escape vulnerability by monitoring for unhandled promise rejections containing ''TypeError: Cannot convert a Symbol value to a string''.'
    platform: sigma
    severity: critical
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A sandbox escape vulnerability has been identified in vm2 versions 3.10.5 and earlier. This vulnerability enables malicious sandboxed code to crash the host Node.js process through a crafted `Promise` constructor that triggers an unhandled rejection. The root cause lies in the fact that Promise executor errors are not adequately caught and sanitized before they can propagate as unhandled rejections to the host process. This results in an immediate process crash, effectively causing a denial-of-service condition. Notably, the `allowAsync: false` setting, intended to mitigate asynchronous code execution, does not prevent this vulnerability and, paradoxically, can exacerbate the issue by blocking `.catch()` handlers, thereby guaranteeing that rejections remain unhandled. The CVE-2026-22709 patch (v3.10.2) only sanitized `.then()` and `.catch()` callback chains but left the executor-to-unhandledRejection path completely open.

## Attack Chain

1.  Attacker crafts malicious JavaScript code designed to be executed within a vm2 sandbox.
2.  The malicious code constructs a `Promise` object using the `Promise` constructor.
3.  Within the `Promise` executor function, an `Error` object is created.
4.  The `Error` object's `name` property is set to a `Symbol()`.
5.  The code then attempts to access the `stack` property of the `Error` object, triggering V8's internal `FormatStackTrace` function.
6.  `FormatStackTrace` attempts `Symbol.toString()`, resulting in a host-realm `TypeError`.
7.  Because no `.catch()` handler is attached, the error becomes an unhandled rejection.
8.  The unhandled rejection propagates to the host Node.js process, causing it to crash.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service (DoS) condition. A single malicious request can crash the entire host Node.js process, disrupting service for all concurrent users. The persistent nature of this DoS, coupled with the ease of triggering it, renders the application unavailable even with standard recovery mechanisms like Docker restart policies or Kubernetes liveness probes. The attacker only needs to send a small request (approximately 150 bytes) to bring down the entire server, demonstrating a high amplification factor. All applications using vm2 are vulnerable, regardless of the `allowAsync` setting.

## Recommendation

*   Upgrade to a patched version of vm2 that addresses this vulnerability. As of this writing, no patched version exists, but monitor the project for updates.
*   Implement rate limiting on API endpoints that execute user-provided JavaScript code to reduce the impact of DoS attacks.
*   Deploy the Sigma rule "Detect vm2 Sandbox Escape Attempt via Symbol Error Name" to identify attempts to exploit this vulnerability within your environment.
*   Monitor application logs for unhandled promise rejections, which could indicate exploitation attempts.
*   Consider implementing a custom error handler within the vm2 sandbox to catch and sanitize errors before they can propagate to the host process.
