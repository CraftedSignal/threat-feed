---
title: Fastify accepts-serializer Denial of Service via Unbounded Accept Header Cache Growth
slug: 2024-01-fastify-dos
description: The @fastify/accepts-serializer package is vulnerable to a denial of service (DoS) attack due to unbounded cache growth, where an attacker can send many distinct Accept header variants, causing the cache to grow unbounded, exhausting the Node.js heap, and crashing the process.
date: "2026-05-08T17:13:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - denial-of-service
  - fastify
products:
  - '@fastify/accepts-serializer (<= 6.0.3)'
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-7768
    cvss: 7.5
    epss: 0.0004
references:
  - https://github.com/advisories/GHSA-qxhc-wx3p-2wmg
rules:
  - title: Detect CVE-2026-7768 Exploitation Attempts via High Volume of Unique Accept Headers
    description: Detects CVE-2026-7768 exploitation attempts by monitoring the number of unique Accept headers within a short time frame
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
  - title: Detect CVE-2026-7768 Potential Exploitation - Excessive Memory Consumption
    description: Detects potential CVE-2026-7768 exploitation by monitoring for significant increases in memory consumption by the Node.js process hosting the Fastify application.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `@fastify/accepts-serializer` package, versions 6.0.3 and earlier, is susceptible to a denial-of-service (DoS) vulnerability. This vulnerability arises from the package's caching mechanism for serializer-selection results, which are keyed by the request's `Accept` header. The cache lacks both a size limit and an eviction policy, making it vulnerable to unbounded growth. An unauthenticated attacker can exploit this by sending numerous distinct `Accept` header variants. Under sustained load, this can exhaust the Node.js heap memory, ultimately causing the process to crash. Defenders should upgrade to version 6.0.4 or later where the cache is bounded.

## Attack Chain

1. An attacker identifies a Fastify application utilizing the `@fastify/accepts-serializer` package version 6.0.3 or earlier.
2. The attacker crafts HTTP requests with unique variations of the `Accept` header.
3. These requests are sent to the target Fastify application.
4. The `@fastify/accepts-serializer` package caches the serializer selection result based on the unique `Accept` header received in each request.
5. The attacker floods the application with a high volume of requests, each containing a slightly different `Accept` header.
6. The cache grows without bounds, consuming an increasing amount of memory.
7. The Node.js heap becomes exhausted due to the unbounded cache growth.
8. The Fastify application crashes, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, rendering the affected Fastify application unavailable. The impact depends on the criticality of the application; a critical service outage can cause significant disruption and financial losses. While the exact number of affected applications is unknown, any Fastify application using a vulnerable version of `@fastify/accepts-serializer` is susceptible. An attacker can trigger the crash with a relatively small number of requests per second, making detection challenging.

## Recommendation

*   Upgrade to `@fastify/accepts-serializer` version 6.0.4 or later to patch CVE-2026-7768.
*   Monitor web server logs for a sudden increase in requests with diverse `Accept` headers, using a rule based on the `webserver` category, to detect potential exploitation attempts.
*   Implement resource monitoring on systems running Fastify applications to detect abnormal memory usage patterns indicative of the DoS attack.
