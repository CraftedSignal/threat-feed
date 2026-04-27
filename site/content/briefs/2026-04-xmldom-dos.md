---
title: xmldom Uncontrolled Recursion DoS Vulnerability
slug: 2026-04-xmldom-dos
description: The xmldom library is vulnerable to a denial-of-service (DoS) attack due to uncontrolled recursion in XML serialization leading to application crashes.
date: "2026-04-23T12:00:00Z"
severities:
  - medium
tags:
  - dos
  - xmldom
  - recursion
  - javascript
products:
  - xmldom
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-2v35-w6hq-6mfw
rules:
  - title: Detect Excessive XML Nesting Depth via Process Crash
    description: Detects process crashes due to stack exhaustion while processing XML, potentially indicating a DoS attack using xmldom.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - application
      - nodejs
  - title: Detect Deeply Nested XML Structures
    description: Detects XML documents with an excessively deep nesting level, which could indicate a potential DoS attack.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `xmldom` library is susceptible to a denial-of-service (DoS) vulnerability due to uncontrolled recursion in XML serialization. Seven recursive traversals within `lib/dom.js` lack depth limits, causing a `RangeError: Maximum call stack size exceeded` and crashing the application when processing deeply nested XML documents. Publicly disclosed on 2026-04-06, the vulnerability impacts multiple functions, including `normalize()`, `XMLSerializer.serializeToString()`, and others related to DOM…
