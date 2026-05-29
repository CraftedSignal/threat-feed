---
title: Gotenberg Denial-of-Service Vulnerability via Multipart downloadFrom Handling
slug: 2026-05-gotenberg-dos
description: Gotenberg is vulnerable to a remote denial-of-service (DoS) in multipart `downloadFrom` handling, where a crafted multipart request with multiple `downloadFrom` entries causes concurrent goroutines to write to shared maps without synchronization, leading to process termination.
date: "2026-05-29T16:57:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - race-condition
  - webserver
vendors:
  - Gotenberg
products:
  - Gotenberg (>= 8.10.0, <= 8.32.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-vp73-vjw8-8f32
  - CVE-2026-45742
rules:
  - title: Detect CVE-2026-45742 Exploitation Attempt — Gotenberg downloadFrom DoS
    description: Detects potential exploitation attempts of CVE-2026-45742 by monitoring for HTTP POST requests to common Gotenberg endpoints with excessive 'downloadFrom' parameters, indicative of a DoS attack. This rule looks for POST requests to specific URI stems and checks if the request body (form data) contains a large number of 'downloadFrom' parameters.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
  - title: Detect CVE-2026-45742 Exploitation Attempt — Gotenberg Multipart downloadFrom DoS
    description: Detects attempts to exploit CVE-2026-45742 in Gotenberg by monitoring for multipart POST requests to known API endpoints, focusing on the presence of the 'downloadFrom' field in the multipart data. This rule flags requests where the content type is multipart/form-data and the body contains the 'downloadFrom' parameter, potentially indicating an attempt to trigger the concurrent map writes vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
rules_count: 2
---

Gotenberg versions 8.10.0 through 8.32.0 are susceptible to a remote denial-of-service (DoS) vulnerability due to a race condition in how it handles multipart requests with multiple `downloadFrom` entries. This vulnerability arises because the `newContext` function, responsible for parsing multipart requests, initiates concurrent goroutines for each `downloadFrom` entry. These goroutines then attempt to write to shared maps without proper synchronization, leading to a fatal runtime crash due to concurrent map writes. The vulnerable `downloadFrom` feature was introduced in commit `f2b6bd3d`. In the default Gotenberg configuration, the `downloadFrom` feature is enabled, and authentication is disabled, making exposed instances vulnerable to unauthenticated remote attackers.

## Attack Chain

1. An attacker sends a crafted HTTP POST request to a Gotenberg multipart conversion endpoint.
2. The request includes a `Content-Type` header set to `multipart/form-data`.
3. The request contains a `downloadFrom` field with a JSON payload consisting of multiple URLs.
4. The `newContext` function parses the multipart request and extracts the `downloadFrom` field.
5. For each URL in the `downloadFrom` payload, a new goroutine is spawned using `errgroup.Go()`.
6. Each goroutine attempts to download the file from the specified URL.
7. After downloading (or failing to download), each goroutine attempts to write to shared maps (`ctx.files`, `ctx.diskToOriginal`, `ctx.filesByField`) within the request context.
8. Due to the lack of synchronization mechanisms, concurrent writes to these maps occur, resulting in a runtime crash (fatal error: concurrent map writes), causing a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service (DoS) condition. Any Gotenberg deployment that exposes multipart conversion endpoints with the `downloadFrom` feature enabled is potentially vulnerable. The default configuration, where `downloadFrom` is enabled and authentication is disabled, makes internet-exposed deployments susceptible to unauthenticated process termination. This vulnerability directly impacts the availability of the Gotenberg service but does not compromise confidentiality or integrity.

## Recommendation

*   Upgrade to Gotenberg version 8.33.0 or later, which contains the fix for CVE-2026-45742.
*   If upgrading is not immediately feasible, disable the `downloadFrom` feature in Gotenberg's configuration to mitigate the vulnerability.
*   Monitor web server logs for POST requests to multipart conversion endpoints containing a large number of `downloadFrom` parameters, which could indicate an attempted exploitation.
