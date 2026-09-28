---
title: Angular SSR Denial of Service via Malformed DOCTYPE
slug: 2026-09-angular-ssr-dos
description: A high-severity denial-of-service vulnerability in @angular/platform-server allows remote unauthenticated attackers to crash the Node.js event loop via a malformed DOCTYPE declaration.
date: "2026-09-28T22:15:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - angular
  - nodejs
  - cve-2026-101895
vendors:
  - Google
products:
  - Angular platform-server (>= 22.0.0, < 22.1.6)
  - Angular platform-server (>= 21.0.0, < 21.2.23)
  - Angular platform-server (>= 20.0.0, < 20.3.31)
  - Angular platform-server (<= 19.2.25)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The HTML parser enters an infinite synchronous loop, pegging CPU utilization at 100% and completely freezing the Node.js server process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f67j-2jqw-jpq7
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: 'Upgrade @angular/platform-server to fixed versions: 22.1.6, 21.2.23, 20.3.31, or > 19.2.25'
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version ranges for remediation.
  mitigation_plan:
    - priority: immediate
      action: Replace [innerHTML] bindings with [textContent] or {{ }} interpolation for untrusted user inputs
      owner: Application Security
      addresses: CVE-2026-101895
      evidence: Source provides explicit workarounds for reachability.
---

A Denial of Service (DoS) vulnerability (CVE-2026-101895) exists in the @angular/platform-server library due to its reliance on the 'domino' DOM parser. When an Angular application performs server-side rendering (SSR) and processes untrusted input through template bindings like [innerHTML], the library may encounter a malformed DOCTYPE declaration ending with whitespace before the End-of-File (EOF) marker.

The underlying issue originates in the HTML parser's tokenizer, which fails to advance the character pointer when encountering an EOF condition in the after_doctype_name_state. This triggers an infinite synchronous loop, consuming 100% of the CPU and effectively locking the single-threaded Node.js process. This vulnerability affects multiple branches of the Angular platform-server, including versions in the 19.x, 20.x, 21.x, and 22.x series. Because the loop occurs synchronously within the event loop, the application becomes unresponsive to all concurrent and subsequent requests until the process is manually restarted.

## Impact

The vulnerability allows unauthenticated remote attackers to trigger a complete Denial of Service on any Angular application utilizing SSR that binds untrusted user input to DOM-rendering properties. Success leads to an immediate hang of the Node.js server process, causing service outages for all users. The flaw is particularly critical for enterprise applications that rely on server-side rendering for SEO or performance.

## Recommendation

* Patch immediately: Upgrade @angular/platform-server to the fixed versions (>= 22.1.6, >= 21.2.23, >= 20.3.31, or > 19.2.25).
* Remediate code: Audit the codebase for instances where untrusted user input is bound directly to `[innerHTML]` in server-rendered templates.
* Implement input validation: Use standard text interpolation `{{ userInput }}` or `[textContent]` instead of raw HTML rendering when the input source is user-controlled.
* Apply perimeter filtering: Implement server-side input sanitization to strip or reject input strings matching the regex `/^<!DOCTYPE/i`.
