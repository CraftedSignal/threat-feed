---
title: Stack Exhaustion Vulnerability in lopdf Rust Library
slug: 2026-10-lopdf-stack-overflow
description: The lopdf Rust library is vulnerable to stack exhaustion via unbounded recursion when parsing deeply nested PDF objects, allowing unauthenticated attackers to cause a denial-of-service via SIGABRT.
date: "2026-10-16T22:28:51Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - lopdf (< 0.42.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A small crafted PDF whose Catalog contains a deeply nested array... exhausts the call stack and aborts the process with SIGABRT.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6fj4-rcr3-r7rr
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade all instances of the lopdf crate to version 0.42.0 or later
      owner: Development
      due: 48h
      evidence: Fixed in 0.42.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade lopdf to 0.42.0
      owner: Development
      addresses: lopdf stack overflow
      evidence: The advisory states the vulnerability is fixed in 0.42.0.
---

The Rust library `lopdf` (versions prior to 0.42.0) contains a vulnerability in its document parsing logic within `lopdf::Document::load_mem` and related entry points. The parser recursively processes nested PDF arrays and dictionaries without implementing a depth limit. By supplying a specially crafted PDF file containing approximately 10,000 levels of nested objects (e.g., `[[[[...]]]]`), an attacker can trigger a stack overflow that results in a process-terminating `SIGABRT`. 

Because this termination occurs as a non-recoverable abort rather than a standard Rust `panic!`, the crash cannot be intercepted by `catch_unwind` handlers. Any service that uses `lopdf` to process untrusted or user-supplied PDF input is susceptible to this denial-of-service (DoS) attack. The attack requires only a small file (approximately 21 KB) to crash the target application. This issue highlights the danger of unbounded recursion when handling complex file formats.

## Impact

Successful exploitation results in a denial-of-service condition for the affected application or service. Any system utilizing `lopdf` to ingest user-uploaded files, process PDF documents from email attachments, or handle API-based PDF generation is at risk. Given that the crash is an unrecoverable `SIGABRT`, affected services will experience complete process interruption until restarted, potentially leading to significant downtime in environments that rely on automated PDF processing.

## Recommendation

1. Update the `lopdf` dependency to version 0.42.0 or later, which implements a maximum object-nesting depth to prevent unbounded recursion.
2. Implement input validation at the application level to reject or pre-scan PDF files for excessive nesting depth before passing them to the `lopdf` parsing functions.
3. Where possible, run PDF parsing logic in a sandboxed or isolated process with resource limits to minimize the impact of crashes on core service infrastructure.
