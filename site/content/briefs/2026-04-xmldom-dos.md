---
title: xmldom Uncontrolled Recursion DoS Vulnerability
slug: 2026-04-xmldom-dos
description: The xmldom library is vulnerable to a denial-of-service (DoS) attack due to uncontrolled recursion in XML serialization leading to application crashes.
date: "2026-04-23T12:00:00Z"
type: coverage
types:
  - coverage
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

The `xmldom` library is susceptible to a denial-of-service (DoS) vulnerability due to uncontrolled recursion in XML serialization. Seven recursive traversals within `lib/dom.js` lack depth limits, causing a `RangeError: Maximum call stack size exceeded` and crashing the application when processing deeply nested XML documents. Publicly disclosed on 2026-04-06, the vulnerability impacts multiple functions, including `normalize()`, `XMLSerializer.serializeToString()`, and others related to DOM manipulation. This issue arises from the library's pure-JavaScript recursive implementation of DOM operations, which exhausts the call stack. Exploitation requires no authentication or special options, affecting applications that process attacker-controlled XML using vulnerable `xmldom` versions ( < 0.8.13, >= 0.9.0 and < 0.9.10, and <= 0.6.0).

## Attack Chain

1. An attacker crafts a malicious XML document with deeply nested elements.
2. The vulnerable application receives and parses the crafted XML document using `DOMParser.parseFromString()`.
3. The application subsequently calls one of the affected DOM operations, such as `normalize()`, `serializeToString()`, `getElementsByTagName()`, or `cloneNode(true)`.
4. The affected function initiates a recursive traversal of the deeply nested XML structure within `lib/dom.js`.
5. Each level of nesting consumes a JavaScript call stack frame.
6. The recursive calls continue until the JavaScript engine's call stack is exhausted.
7. A `RangeError: Maximum call stack size exceeded` exception is thrown.
8. The application crashes due to the uncaught exception, leading to a denial of service.

## Impact

Successful exploitation results in a denial-of-service condition. Any service parsing attacker-controlled XML with a vulnerable version of `xmldom` can be crashed by a single crafted payload. This can lead to failed request processing. In deployments where uncaught exceptions terminate the worker or process, the impact can extend beyond a single request and disrupt service availability more broadly. Tests show that stack exhaustion occurs with nesting depths between 5,000 and 10,000 levels depending on the operation.

## Recommendation

*   Upgrade `@xmldom/xmldom` to version >= 0.8.13 or >= 0.9.10 to remediate CVE-2026-41673.
*   If upgrading is not immediately feasible, consider implementing input validation to limit the nesting depth of XML documents processed by applications using `xmldom`.
*   Monitor application logs for `RangeError: Maximum call stack size exceeded` exceptions originating from `lib/dom.js`, which could indicate exploitation attempts.
