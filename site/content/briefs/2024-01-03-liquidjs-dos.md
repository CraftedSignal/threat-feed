---
title: liquidjs Denial of Service via Circular Block Reference
slug: 2024-01-03-liquidjs-dos
description: A vulnerability in liquidjs versions prior to 10.25.7 allows for denial of service due to a circular block reference in the layout, causing an infinite recursive loop that exhausts memory and crashes the Node.js process.
date: "2024-01-03T12:00:00Z"
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

The liquidjs template engine, in versions prior to 10.25.7, is vulnerable to a denial-of-service (DoS) attack. This vulnerability stems from the improper handling of circular block references within the `{% layout %}` and `{% block %}` tags. When a template contains a nested block with the same name as an outer block, the rendering process enters an infinite recursive loop. This loop rapidly consumes available memory, leading to a "JavaScript heap out of memory" error and the subsequent…
