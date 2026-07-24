---
title: js-yaml Denial of Service via Exponential Parsing Time in Flow Collections
slug: 2026-07-js-yaml-dos
description: A denial of service vulnerability exists in the js-yaml library (versions 5.0.0 through 5.2.1) due to an exponential parsing time bug in flow collections, allowing attackers to craft a small YAML document which, when processed by `load()` or `loadAll()` functions, consumes significant CPU resources and blocks the Node.js event loop.
date: "2026-07-24T16:50:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - yaml
  - javascript
  - vulnerability
vendors:
  - nodeca
products:
  - js-yaml
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Parsing a small YAML document can take exponential time. An application that calls `load()` or `loadAll()` on untrusted input can be hung by a payload under 200 bytes.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pm4m-ph32-ghv5
---

A critical denial of service vulnerability exists within the `js-yaml` JavaScript library, affecting versions 5.0.0 through 5.2.1. This flaw, reported by GHSA, stems from an exponential parsing time issue when handling specific deeply nested flow collections within YAML documents. Attackers can craft a small, under 200-byte YAML payload that, when processed by a vulnerable application using `js-yaml`'s `load()` or `loadAll()` functions, causes the parser to re-evaluate sections multiple times. This results in a computational complexity of O(2^n), where 'n' is the nesting depth. The excessive CPU consumption effectively blocks the Node.js event loop, rendering the application unresponsive and leading to a complete denial of service. The vulnerability requires no special YAML features like anchors or non-default options, making it broadly exploitable against applications processing untrusted YAML input.

## Attack Chain

1. Attacker crafts a malicious YAML payload specifically designed to trigger exponential parsing.
2. The crafted payload contains deeply nested flow sequences, specifically patterns such as `[ [ ... ] : 0 ]` within a `key: value` structure.
3. The attacker sends this small (e.g., under 200 bytes) YAML document to a target application that uses the `js-yaml` library (versions 5.0.0-5.2.1) for parsing.
4. The application invokes `js-yaml.load()` or `js-yaml.loadAll()` to parse the untrusted YAML input.
5. During the parsing process, `js-yaml` encounters the nested flow collections and, due to an underlying parsing inefficiency, repeatedly rewinds and re-parses entries multiple times.
6. This re-parsing leads to an exponential increase in processing time (O(2^n)) and consumes significant CPU resources, even for relatively shallow nesting (e.g., 30 levels taking over 2 minutes).
7. The Node.js event loop of the target application becomes blocked by the intensive parsing operation, preventing it from handling any further requests.
8. The application becomes unresponsive and unavailable to legitimate users, resulting in a complete denial of service.

## Impact

This vulnerability leads to a denial of service, where a single, small, specially crafted YAML request can monopolize a server's CPU for minutes or even longer. For example, a payload with 22 nesting levels can take approximately 1 second to parse, while 26 levels can take 17 seconds, and 30 levels can exceed 2 minutes, all from an input under 200 bytes. This resource exhaustion blocks the Node.js event loop, causing the entire application to become unresponsive and unavailable to other users or services. Any application processing untrusted YAML input via `js-yaml` versions 5.0.0 through 5.2.1 is susceptible, potentially affecting web servers, APIs, or configuration management systems across various sectors that rely on YAML for data interchange.

## Recommendation

* Patch `js-yaml` to a version greater than 5.2.1 immediately to mitigate the exponential parsing vulnerability.
* Implement strict input validation and sanitization for all untrusted YAML input processed by applications using the `js-yaml` library.
* Deploy the provided YAML payload as a test case in development environments to identify any remaining vulnerable `js-yaml` instances.
