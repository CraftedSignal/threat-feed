---
title: Fulgur HTML-to-PDF Denial of Service via Resource Exhaustion
slug: 2026-09-fulgur-dos
description: Fulgur versions prior to 0.26.0 are vulnerable to a denial-of-service attack where an attacker-supplied HTML payload causes CPU and memory exhaustion by forcing the rendering of thousands of blank PDF pages.
date: "2026-09-17T19:10:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:fulgur-rs:fulgur:*:*:*:*:*:rust:*:*
vendors:
  - fulgur-rs
products:
  - fulgur (< 0.26.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A few bytes of HTML therefore amplified into roughly MAX_PAGES (10,000) blank pages; the renderer allocates and runs a per-page loop over them, producing CPU and memory exhaustion.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4rf6-qx84-q9fv
  - https://github.com/fulgur-rs/fulgur/pull/575
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade Fulgur library to version 0.26.0 or later.
      owner: Development
      due: 48h
      evidence: 'Fixed in 0.26.0 (PR #575).'
  mitigation_plan:
    - priority: immediate
      action: Implement strict validation for CSS height/vh units on user-supplied HTML.
      owner: Development
      addresses: CVE-2026-68537
      evidence: Validate or constrain untrusted CSS (in particular very large height / vh on elements) before passing HTML to fulgur.
---

Fulgur is a Rust-based library for converting HTML/CSS into PDF documents. Versions prior to 0.26.0 contain a critical resource exhaustion vulnerability identified as CVE-2026-68537. The library's existing \"childless-collapse\" defense, intended to prevent the rendering of excessively large or pathologically tall elements, was flawed because it only checked for tag-specific \"replaced content.\" Consequently, non-painting replaced elements, such as images with missing sources, hidden visibility, undecodable formats, or empty `<svg>` elements, could bypass this defense. 

An attacker can exploit this by submitting a small HTML payload containing these specific elements with pathologically tall height attributes. This forces the renderer to allocate and process up to 10,000 blank pages, leading to significant CPU and memory consumption. In deployments where Fulgur processes untrusted input from network-facing services, this leads to a denial of service for the host and any co-tenants.

## Attack Chain

1. Attacker identifies a network-facing application that uses the Fulgur library to generate PDFs from user-provided HTML.
2. Attacker crafts a malicious HTML payload containing a childless box (e.g., `<img src=\"\">` or `<svg>`) with an extreme CSS `height` value.
3. The attacker submits the payload to the target application's PDF generation endpoint.
4. The application passes the untrusted HTML/CSS to the vulnerable Fulgur library (versions < 0.26.0).
5. The library's rendering engine encounters the non-painting replaced element and fails to trigger the childless-collapse logic due to the flawed tag-only check.
6. The renderer attempts to allocate and process the large number of pages defined by the malicious CSS.
7. System resources (CPU and memory) are exhausted, leading to service degradation or total crash.

## Impact

Successful exploitation results in a denial-of-service condition, impacting the availability of the host application. In multi-tenant environments, this impact extends to other users sharing the same server infrastructure. The attack is highly effective as it requires only a few bytes of HTML input to trigger maximum resource allocation.

## Recommendation

Prioritized actions for security and development teams:
- Upgrade the Fulgur library to version 0.26.0 or later immediately, as this version removes the flawed tag-only gate and correctly collapses all pathologically tall boxes.
- If immediate patching is not feasible, implement strict input validation for untrusted HTML/CSS before passing it to the library. Specifically, constrain or sanitize large height and `vh` CSS units.
- Review applications using Fulgur for exposure to user-supplied HTML and ensure that rendering tasks are performed within containerized or sandboxed environments to limit resource impact.
