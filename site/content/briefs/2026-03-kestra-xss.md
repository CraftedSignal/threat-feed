---
title: Kestra Orchestration Platform XSS Vulnerability (CVE-2026-33664)
slug: 2026-03-kestra-xss
description: Kestra versions up to 1.3.3 are vulnerable to a cross-site scripting (XSS) vulnerability (CVE-2026-33664) allowing arbitrary JavaScript execution by viewing crafted flow metadata.
date: "2026-03-27T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - kestra
  - xss
  - cve-2026-33664
  - orchestration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33664
rules:
  - title: Detect Suspicious Kestra Flow Metadata with JavaScript Injection
    description: Detects potential XSS attacks in Kestra by identifying suspicious patterns indicative of JavaScript injection in flow metadata.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Kestra Flow Metadata with JavaScript Event Handlers
    description: Detects potential XSS attacks in Kestra by identifying suspicious patterns indicative of JavaScript injection in flow metadata using event handlers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kestra, an open-source, event-driven orchestration platform, is vulnerable to a reflected cross-site scripting (XSS) vulnerability, identified as CVE-2026-33664. This flaw resides in versions up to and including 1.3.3. The application fails to properly sanitize user-supplied flow YAML metadata fields, specifically `description`, `inputs[].displayName`, and `inputs[].description`. These fields are rendered through the `Markdown.vue` component with `html: true`, resulting in unsanitized HTML…
