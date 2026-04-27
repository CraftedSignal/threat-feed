---
title: Contour HTTPProxy Lua Code Injection via Cookie Path Rewrite
slug: 2024-01-09-contour-lua-injection
description: Contour's Cookie Rewriting feature is vulnerable to Lua code injection; an attacker with RBAC permissions to create or modify HTTPProxy resources can craft a malicious value in the `spec.routes[].cookieRewritePolicies[].pathRewrite.value` or `spec.routes[].services[].cookieRewritePolicies[].pathRewrite.value` fields, resulting in arbitrary code execution in the Envoy proxy.
date: "2024-01-09T12:00:00Z"
severities:
  - high
tags:
  - contour
  - lua
  - code-injection
  - httpproxy
  - cve-2026-41246
vendors:
  - Project Contour
products:
  - Contour
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-x4mj-7f9g-29h4
rules:
  - title: Detect HTTPProxy resource creation/modification with Lua Injection Pattern
    description: Detects creation or modification of HTTPProxy resources that contain suspicious Lua code patterns in the cookie rewrite policy fields
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect HTTPProxy resource creation/modification with suspicious cookie path rewrite value
    description: Detects creation or modification of HTTPProxy resources that contain suspicious characters within the cookie path rewrite value
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Project Contour is susceptible to Lua code injection within its cookie rewriting functionality. The vulnerability arises from insufficient sanitization when user-controlled values are interpolated into Lua source code using Go's `text/template`. This affects Contour versions 1.19.0 through 1.33.3. An attacker with the ability to create or modify `HTTPProxy` resources can inject arbitrary Lua code by crafting malicious values in `spec.routes[].cookieRewritePolicies[].pathRewrite.value` or…
