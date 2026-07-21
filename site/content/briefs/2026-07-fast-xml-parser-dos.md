---
title: 'fast-xml-parser: Repeated DOCTYPE Declarations Bypass Entity Expansion Limits Leading to DoS'
slug: 2026-07-fast-xml-parser-dos
description: A vulnerability in fast-xml-parser allows an attacker to bypass entity expansion limits by crafting XML documents with multiple DOCTYPE declarations, leading to excessive CPU usage, memory exhaustion, and denial of service.
date: "2026-07-21T22:08:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability-exploitation
  - software-supply-chain
products:
  - fast-xml-parser (>= 5.9.3, < 5.10.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: This allows a crafted XML document to exceed the configured entity-expansion limits and can cause excessive CPU use, event-loop blocking, memory exhaustion, and process termination.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8r6m-32jq-jx6q
---

A critical vulnerability (tracked as GHSA-8r6m-32jq-jx6q) in the `fast-xml-parser` library, versions greater than or equal to 5.9.3 and less than 5.10.1, allows attackers to trigger a denial of service (DoS) by crafting malicious XML documents. The library improperly handles multiple `DOCTYPE` declarations within a single XML document. Each `DOCTYPE` declaration processes its entities through `@nodable/entities`' `addInputEntities()` function, which unexpectedly resets the entity expansion counters (`maxTotalExpansions` and `maxExpandedLength`) each time it is called. This design flaw enables an attacker to repeatedly reset these limits, allowing a crafted XML document to consume excessive system resources, leading to high CPU utilization, event-loop blocking, severe memory exhaustion, and ultimately process termination. This vulnerability has been present in affected versions since 5.9.3 and impacts any application or service utilizing the vulnerable `fast-xml-parser` library.

## Attack Chain

1. An attacker crafts a malicious XML document containing multiple `DOCTYPE` declarations.
2. The crafted XML document is supplied as input to a system or application utilizing the vulnerable `fast-xml-parser` library (versions >= 5.9.3, < 5.10.1).
3. The `fast-xml-parser` library begins parsing the XML document.
4. Upon encountering each `DOCTYPE` declaration, the parser passes its entities to the `@nodable/entities` library, which calls `addInputEntities()`.
5. The `addInputEntities()` function, when called multiple times, unexpectedly resets internal entity expansion counters (e.g., `maxTotalExpansions`, `maxExpandedLength`).
6. Due to the repeated resets, the attacker's crafted XML document can exceed the configured entity-expansion limits that would normally prevent resource exhaustion.
7. The parsing process consumes excessive CPU cycles and memory.
8. The host system experiences event-loop blocking, memory exhaustion, and eventually the application process terminates, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial of service (DoS) condition on the affected system or application. An attacker can cause excessive CPU utilization, block the event loop, exhaust available memory, and force the termination of the parsing process or the entire application. This can lead to significant service disruptions, system instability, and potential data loss if the application cannot recover gracefully. While specific victim counts are not available, any organization using vulnerable versions of `fast-xml-parser` in their web applications, APIs, or backend services is susceptible to this attack, with potential impact on critical business operations.

## Recommendation

* Update `fast-xml-parser` to version 5.10.1 or later to patch the vulnerability.
* Manually implement input validation to check for and reject XML documents containing multiple `DOCTYPE` declarations, especially if immediate patching is not possible.
* Ensure the `processEntity` flag in `fast-xml-parser` configurations is kept off (default behavior) to reduce exposure, though this is not a complete mitigation for this specific vulnerability.
