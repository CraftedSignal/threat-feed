---
title: Contour HTTPProxy Lua Code Injection via Cookie Path Rewrite
slug: 2024-01-09-contour-lua-injection
description: Contour's Cookie Rewriting feature is vulnerable to Lua code injection; an attacker with RBAC permissions to create or modify HTTPProxy resources can craft a malicious value in the `spec.routes[].cookieRewritePolicies[].pathRewrite.value` or `spec.routes[].services[].cookieRewritePolicies[].pathRewrite.value` fields, resulting in arbitrary code execution in the Envoy proxy.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
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

Project Contour is susceptible to Lua code injection within its cookie rewriting functionality. The vulnerability arises from insufficient sanitization when user-controlled values are interpolated into Lua source code using Go's `text/template`. This affects Contour versions 1.19.0 through 1.33.3. An attacker with the ability to create or modify `HTTPProxy` resources can inject arbitrary Lua code by crafting malicious values in `spec.routes[].cookieRewritePolicies[].pathRewrite.value` or `spec.routes[].services[].cookieRewritePolicies[].pathRewrite.value`. While the injected code executes within the attacker's own route, the shared nature of the Envoy proxy allows for potential escalation of privileges, including reading Envoy's xDS client credentials and causing denial of service for other tenants. This vulnerability is resolved in Contour versions v1.33.4, v1.32.5, and v1.31.6.

## Attack Chain

1. An attacker gains RBAC permissions to create or modify `HTTPProxy` resources within the Contour environment.
2. The attacker crafts a malicious `HTTPProxy` resource containing a `cookieRewritePolicies` section.
3. Within the `cookieRewritePolicies`, the attacker injects Lua code into the `pathRewrite.value` field.
4. The attacker applies the crafted `HTTPProxy` resource, deploying the malicious configuration to Contour.
5. Contour, using the Envoy proxy, processes the `HTTPProxy` resource, interpolating the attacker-controlled value into the Lua filter.
6. When traffic is processed on the attacker's route, the injected Lua code executes within the Envoy proxy.
7. The injected Lua code attempts to read Envoy's xDS client credentials from the filesystem.
8. The attacker uses the obtained xDS client credentials to read all Contour xDS configuration, including TLS certificates and private keys of other tenants, or to cause a denial of service for other tenants sharing the Envoy instance.

## Impact

A successful exploit allows attackers to execute arbitrary code within the Envoy proxy, potentially leading to credential theft and denial of service. Specifically, an attacker can steal TLS certificates and private keys of other tenants within the Contour environment. This could compromise sensitive data and disrupt services. If xDS credentials can be obtained, an attacker can then modify/exfiltrate service mesh configuration details.

## Recommendation

*   Upgrade Contour to version v1.33.4, v1.32.5, or v1.31.6 to remediate the Lua code injection vulnerability as described in the overview.
*   Monitor HTTPProxy resource creation and modification events for suspicious patterns or unexpected values in the `spec.routes[].cookieRewritePolicies[].pathRewrite.value` and `spec.routes[].services[].cookieRewritePolicies[].pathRewrite.value` fields.
*   Implement RBAC least privilege principles to restrict access to creating and modifying `HTTPProxy` resources, mitigating the initial access vector required to exploit this vulnerability.
