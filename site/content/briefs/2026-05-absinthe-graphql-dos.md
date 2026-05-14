---
title: Absinthe GraphQL Fragment Validation Denial-of-Service (CVE-2026-43967)
slug: 2026-05-absinthe-graphql-dos
description: A denial-of-service vulnerability exists in the Absinthe GraphQL library (versions 1.2.0 to 1.10.1), where an unauthenticated attacker can exhaust server resources by submitting a crafted GraphQL query with a large number of fragment definitions due to the quadratic complexity of fragment name uniqueness validation.
date: "2026-05-14T13:16:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial of service
  - graphql
  - absinthe
  - algorithmic complexity
  - CVE-2026-43967
vendors:
  - erlang
products:
  - absinthe
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-43967
    epss: 0.00134
references:
  - https://github.com/advisories/GHSA-9mhv-8h52-q7q2
  - https://github.com/absinthe-graphql/absinthe/commit/0b46e3bcc06c0d3797bacd64761b908a84646c1d#diff-e540120c6a98cc1013be110d08e9d029511b9aabd26ad5f7f643c36834caac14
rules:
  - title: Detect Absinthe GraphQL Excessive Fragments (CVE-2026-43967)
    description: Detects CVE-2026-43967 exploitation attempt — Monitors web server logs for GraphQL requests containing an excessive number of fragment definitions, indicating a potential denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
      - cve-2026-43967
    techniques:
      - T1498
    data_sources:
      - webserver
  - title: Detect Large GraphQL Query Size (CVE-2026-43967)
    description: Detects CVE-2026-43967 exploitation attempt — Monitors web server logs for GraphQL requests with abnormally large request sizes, which could indicate a denial-of-service attack by sending a large number of fragments.
    platform: sigma
    severity: medium
    tactics:
      - availability
      - cve-2026-43967
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 2
---

A denial-of-service vulnerability exists in the Absinthe GraphQL library, specifically in versions 1.2.0 through 1.10.1. The vulnerability stems from the inefficient algorithm used to validate the uniqueness of fragment names within a GraphQL query. An unauthenticated attacker can exploit this by sending a specially crafted GraphQL query that contains a large number of fragment definitions. The validation process, which has a time complexity of O(N²), leads to excessive CPU consumption, potentially exhausting server resources and causing a denial of service. No authentication or schema knowledge is required; the attacker only needs to send a large GraphQL query.

## Attack Chain

1.  The attacker crafts a GraphQL query containing a very large number of fragment definitions. Each fragment definition minimally includes the `fragment` keyword, a unique name, the `on` keyword, and a type (`fragment a on T{f}`).
2.  The attacker sends the crafted GraphQL query to the Absinthe GraphQL endpoint via an HTTP POST request. The request body uses the JSON format.
3.  The Absinthe library receives the request and parses the GraphQL query, creating an internal representation of the document including a list of fragments.
4.  The `Absinthe.Phase.Document.Validation.UniqueFragmentNames` module is invoked to validate the uniqueness of the fragment names within the query.
5.  The `run/2` function iterates through each fragment in the `input.fragments` list.
6.  For each fragment, the `process/2` function is called which, in turn, calls `duplicate?/2` to check for duplicates.
7.  `duplicate?/2` performs a linear scan (`Enum.count`) of the entire fragment list to count occurrences of the current fragment's name, resulting in N*N comparisons.
8.  Due to the quadratic complexity, processing the large number of fragments consumes excessive CPU resources, potentially leading to worker exhaustion and denial of service.

## Impact

This vulnerability can lead to a denial-of-service condition on any service that exposes an Absinthe GraphQL endpoint to untrusted callers. A single unauthenticated POST request containing a large number of fragment definitions can tie up a worker process for several seconds. A modest amount of sustained traffic can exhaust the request-handling pool, rendering the service unavailable. The demonstration shows that 20,000 fragments can cause 15 seconds of CPU usage.

## Recommendation

*   Upgrade to Absinthe version 1.10.2 or later, which includes a fix that reduces the complexity of the fragment name uniqueness validation to O(N).
*   Monitor GraphQL endpoints for abnormally large requests containing excessive fragment definitions. Implement rate limiting to mitigate potential denial-of-service attacks.
*   Deploy the Sigma rule `Detect Absinthe GraphQL Excessive Fragments (CVE-2026-43967)` to detect requests with a high number of GraphQL fragments in web server logs.
*   Consider implementing a maximum body size limit on GraphQL requests to prevent attackers from sending extremely large queries. The report mentions Phoenix's default is 8 MB.
