---
title: Cross-Site Scripting Vulnerability in @nuxtjs/mdc
slug: 2026-09-nuxtjs-mdc-xss
description: The @nuxtjs/mdc package contains an XSS vulnerability (CVE-2026-63671) due to improper sanitization of SVG xlink:href attributes and iframe data:text/html sources during markdown parsing.
date: "2026-09-17T01:07:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nuxtjs:mdc:*:*:*:*:*:node.js:*:*
tags:
  - xss
  - web-vulnerability
  - nuxtjs
vendors:
  - NuxtJS
products:
  - '@nuxtjs/mdc (< 0.22.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The @nuxtjs/mdc package fails to properly sanitize specific HTML attributes and URI schemes in markdown parsing, allowing Cross-Site Scripting (XSS).
    confidence_band: high
cves:
  - id: CVE-2026-63671
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-mxm6-v9r6-r94c
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Upgrade @nuxtjs/mdc to 0.22.1 or later
      owner: Development
      due: 48h
      evidence: CVE-2026-63671 patch requirement
  mitigation_plan:
    - priority: immediate
      action: 'Implement strict CSP to block data: URIs and unauthorized javascript execution'
      owner: Security Operations
      addresses: CVE-2026-63671
      evidence: Mitigation for XSS vectors
---

The `@nuxtjs/mdc` package is vulnerable to Cross-Site Scripting (XSS) due to insufficient sanitization of untrusted markdown input (CVE-2026-63671). The library parses markdown into a Vue component tree and uses a sanitizer to block dangerous HTML attributes and URI schemes. However, the sanitizer's attribute-checking logic only validates `href` and `src`, allowing the `xlink:href` attribute on SVG elements to pass through unvalidated. Attackers can inject a `javascript:` URI within an SVG `<a>` tag, which executes in the context of the page's origin when clicked.

Additionally, the sanitizer's deny-list implementation for URI schemes fails to correctly handle `data:` URIs. It compares the `data:` protocol string against the list of forbidden prefixes, causing the check to consistently fail and permitting `<iframe>` elements to load `data:text/html` content. Since `iframe` is not included in the library's list of dangerous tags, this allows the execution of arbitrary script content within an opaque origin. These vulnerabilities exist by default, as the library enables dangerous HTML rendering without requiring custom configuration.

## Impact

Successful exploitation allows attackers to perform XSS attacks against users viewing markdown content rendered by `@nuxtjs/mdc`. This can lead to session hijacking, sensitive data theft, or arbitrary actions performed on behalf of the victim within the application context. The vulnerability affects all implementations of `@nuxtjs/mdc` version 0.22.1 and earlier that process user-supplied markdown.

## Recommendation

* Upgrade `@nuxtjs/mdc` to version 0.22.1 or later immediately to patch the sanitization logic.
* Audit applications currently using `@nuxtjs/mdc` to determine if they render untrusted user input, as this represents the primary threat vector for CVE-2026-63671.
* If upgrading is not immediately possible, implement a secondary layer of sanitization or a strict Content Security Policy (CSP) that restricts `frame-src` and `script-src` to minimize the potential impact of injected scripts.
