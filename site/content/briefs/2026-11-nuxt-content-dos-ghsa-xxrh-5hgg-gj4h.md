---
brief_id: brief-2026-11-11-nuxt-content-dos-ghsa-xxrh-5hgg-gj4h
event_id: brief-2026-11-11-nuxt-content-dos-ghsa-xxrh-5hgg-gj4h
revision: 1
activity_at: "2026-11-11T16:06:04Z"
title: 'Nuxt Content: Unauthenticated SQLite Function Denial of Service'
slug: 2026-11-nuxt-content-dos-ghsa-xxrh-5hgg-gj4h
description: An unauthenticated remote denial-of-service vulnerability in @nuxt/content allows attackers to trigger resource-intensive SQLite functions, blocking the Node.js event loop.
date: "2026-11-11T16:06:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - denial-of-service
  - web-vulnerability
  - npm
  - nuxt
vendors:
  - Nuxt
products:
  - npm/@nuxt/content
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: An unauthenticated remote attacker can craft a single request that forces SQLite to allocate hundreds of megabytes of memory and perform CPU-intensive work, causing server-wide denial of service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c739-vwm9-rgx3
  - https://github.com/advisories/GHSA-xxrh-5hgg-gj4h
rules:
  - title: Detect POST Requests to Nuxt Content Query API
    description: Detects incoming POST requests to the Nuxt Content query endpoint which may be leveraged for resource-exhaustion attacks.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 1
---

The `POST /__nuxt_content/:collection/query` endpoint in `@nuxt/content` contains a validation gap that permits an attacker to execute resource-intensive SQLite built-in functions, such as `randomblob()`, `zeroblob()`, `hex()`, and `length()`. Because `better-sqlite3` processes queries synchronously, these operations block the Node.js event loop, resulting in a server-wide denial of service.

## Attack Chain

1. An unauthenticated attacker sends a crafted POST request to `/__nuxt_content/:collection/query`.
2. The input is processed by `assertSafeQuery`, which only filters specific SQL keywords and fails to block resource-intensive function calls.
3. The malicious SQL is executed synchronously via `better-sqlite3`.
4. The application event loop is blocked, causing service disruption.

## Impact

Successful exploitation results in high-availability impact, as unauthenticated remote attackers can exhaust server CPU and memory resources to force total service disruption.

## Recommendation

Restrict access to the `/__nuxt_content/*/query` endpoint or ensure the application is correctly updated if an official patch is available. Fully static deployments that do not use the API route are not affected.
