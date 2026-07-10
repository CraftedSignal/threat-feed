---
title: LiquidJS Memory Limit Bypass Leads to Denial of Service
slug: 2024-01-03-liquidjs-dos
description: A vulnerability in LiquidJS versions 10.24.0 and earlier allows a threat actor with control over template content to bypass the `memoryLimit` protection mechanism, leading to a denial of service by using reverse range expressions to allocate unlimited memory and a string flattening operation to cause a V8 Fatal error that crashes the Node.js process.
date: "2024-01-03T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - liquidjs
  - denial-of-service
  - template-injection
  - nodejs
vendors:
  - LiquidJS
products:
  - LiquidJS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-9r5m-9576-7f6x
rules:
  - title: Detect LiquidJS Template Injection
    description: Detects HTTP requests containing LiquidJS template syntax, indicative of potential template injection attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LiquidJS Reverse Range Exploitation
    description: Detects HTTP requests that potentially exploit the LiquidJS memory limit bypass using reverse ranges.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in LiquidJS versions 10.24.0 and earlier, allowing attackers with control over Liquid template content to bypass the `memoryLimit` security feature. This bypass is achieved by exploiting reverse range expressions (e.g., `(100000000..1)`) within the template, which causes the internal memory counter to become negative. Subsequently, attackers can construct large strings using the `append` filter, creating a cons-string. When a filter requiring string flattening, such as `replace`, is applied, V8 attempts to allocate a large contiguous memory block, triggering a fatal error that crashes the Node.js process. This vulnerability enables a single HTTP request to cause a service-wide denial of service.

## Attack Chain

1. The attacker crafts a Liquid template containing reverse range expressions, such as `{% for x in (100000000..1) %}{% endfor %}`.
2. These expressions are evaluated by LiquidJS, leading to a negative value being passed to the `memoryLimit.use()` function.
3. The `Limiter.use()` function incorrectly updates the internal memory counter, allowing it to go negative.
4. The attacker then uses the `append` filter to create a large cons-string (e.g., `{% assign s = s | append: s %}` repeated 27 times).
5. This cons-string is logically large (e.g., 134MB) but consumes minimal actual memory.
6. The attacker uses a filter like `replace` that requires flattening the cons-string into a contiguous memory buffer.
7. V8 attempts to allocate a large memory block to flatten the string, exceeding available resources.
8. This triggers a V8 Fatal error, causing the Node.js process to crash and resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability allows an attacker to crash the Node.js process running LiquidJS, leading to a service-wide denial of service. This impacts applications using LiquidJS for templating, especially those that allow user-supplied templates, such as CMS systems, email template editors, and SaaS platforms. A single malicious HTTP request can terminate the entire Node.js process, requiring manual intervention or container restart policies to recover. This issue affects LiquidJS version 10.24.0 and earlier.

## Recommendation

*   Apply appropriate input validation and sanitization to any user-provided Liquid templates to prevent the use of reverse ranges.
*   Monitor web server logs for POST requests containing Liquid template syntax, especially those including reverse range expressions or excessive `append` filter usage, to detect potential exploitation attempts.
*   Consider deploying the Sigma rule `Detect LiquidJS Template Injection` to identify requests with potentially malicious LiquidJS code.
*   Upgrade to a patched version of LiquidJS that addresses this vulnerability, when available.
