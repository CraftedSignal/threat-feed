---
title: liquidjs Denial of Service via Circular Block Reference
slug: 2024-01-03-liquidjs-dos
description: A vulnerability in liquidjs versions prior to 10.25.7 allows for denial of service due to a circular block reference in the layout, causing an infinite recursive loop that exhausts memory and crashes the Node.js process.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - liquidjs
  - denial-of-service
  - template-injection
vendors:
  - liquidjs
products:
  - liquidjs
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-4rc3-7j7w-m548
rules:
  - title: Detect LiquidJS Template DoS
    description: Detects LiquidJS templates with deeply nested blocks, potentially leading to denial of service.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect LiquidJS High Memory Usage
    description: Alerts on abnormally high memory usage by Node.js processes, potentially indicative of a LiquidJS DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The liquidjs template engine, in versions prior to 10.25.7, is vulnerable to a denial-of-service (DoS) attack. This vulnerability stems from the improper handling of circular block references within the `{% layout %}` and `{% block %}` tags. When a template contains a nested block with the same name as an outer block, the rendering process enters an infinite recursive loop. This loop rapidly consumes available memory, leading to a "JavaScript heap out of memory" error and the subsequent crashing of the Node.js process. The vulnerability allows any user capable of submitting a Liquid template to trigger the DoS. This is especially concerning for CMS platforms, email template builders, and multi-tenant SaaS products.

## Attack Chain

1.  An attacker crafts a malicious Liquid template containing circular block references, specifically nesting a block with the same name inside another block. For example, `{% block a %}outer-a {% block a %}inner-a{% endblock %}{% endblock %}`.
2.  The attacker submits this crafted template to an application that uses liquidjs for template rendering. This could be a CMS, email template builder, or any platform allowing user-provided Liquid templates.
3.  The application's liquidjs engine begins rendering the template.
4.  During the rendering process, the engine encounters the nested block structure.
5.  The engine attempts to resolve the block references, resulting in a recursive call to the same block's render function.
6.  This recursive call creates an infinite loop, as the inner block continuously calls the outer block's render function, and vice versa.
7.  The infinite loop causes uncontrolled memory allocation, rapidly consuming all available system memory (up to ~4GB).
8.  The Node.js process running the liquidjs engine crashes with a "FATAL ERROR: JavaScript heap out of memory" error, leading to a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial of service (DoS). Any application that accepts user-provided or user-influenced Liquid templates can be crashed by a single malicious template. The Node.js process is terminated by the operating system due to memory exhaustion, resulting in complete service disruption. The number of potential victims is large, including CMS platforms, email template builders, multi-tenant SaaS products, and static site generators with untrusted input.

## Recommendation

*   Upgrade to liquidjs version 10.25.7 or later to patch CVE-2026-41311.
*   Implement input validation and sanitization for Liquid templates to prevent the submission of malicious code.
*   Monitor Node.js processes for excessive memory consumption, which could indicate a DoS attack.
*   Deploy the Sigma rule `Detect LiquidJS Template DoS` to identify potentially malicious templates based on nested block structures.
