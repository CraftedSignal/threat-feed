---
title: Saleor GraphQL Batch Query Resource Exhaustion Vulnerability (CVE-2026-33756)
slug: 2026-04-saleor-resource-exhaustion
description: Unauthenticated attackers can exploit a resource exhaustion vulnerability (CVE-2026-33756) in Saleor e-commerce platform versions before 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118 by sending a single HTTP request with a large number of GraphQL operations, bypassing query complexity limits and exhausting server resources.
date: "2026-04-09T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - resource-exhaustion
  - graphql
  - cve-2026-33756
  - dos
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-33756
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33756
rules:
  - title: Detect High Volume of GraphQL Queries
    description: Detects HTTP requests containing a large number of GraphQL queries, potentially indicating a resource exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Large HTTP POST Request to GraphQL Endpoint
    description: Detects abnormally large HTTP POST requests to the GraphQL endpoint, potentially indicative of a resource exhaustion attempt.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Saleor, an e-commerce platform, is susceptible to a resource exhaustion vulnerability affecting versions 2.0.0 prior to 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118. This vulnerability stems from the platform's support for query batching, where multiple GraphQL operations can be submitted in a single HTTP request as a JSON array. The absence of an upper limit on the number of operations within a single request allows unauthenticated attackers to bypass per-query complexity limits. By sending a single HTTP request containing a massive number of GraphQL operations, an attacker can exhaust server resources, potentially leading to denial of service. The vulnerability is addressed in versions 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118. Defenders must ensure they are running patched versions.

## Attack Chain

1.  The attacker identifies a Saleor instance running a vulnerable version (prior to 3.23.0a3, 3.22.47, 3.21.54, or 3.20.118).
2.  The attacker crafts a malicious HTTP POST request targeting the GraphQL endpoint (typically `/graphql/`).
3.  The request body contains a JSON array representing a batch of GraphQL queries.
4.  The number of GraphQL operations within the array is excessively large, designed to bypass query complexity limits.
5.  The Saleor server processes the HTTP request, attempting to execute all GraphQL operations within the batch.
6.  Due to the large number of operations, the server's resources (CPU, memory) become heavily utilized.
7.  The server becomes slow or unresponsive to legitimate user requests, causing a denial-of-service condition.
8.  The attacker repeats the process to maintain the denial-of-service state, impacting legitimate users.

## Impact

Successful exploitation of this vulnerability results in resource exhaustion on the Saleor e-commerce platform. This can lead to slow response times, application instability, and ultimately a denial-of-service condition for legitimate users. This vulnerability poses a significant risk to e-commerce businesses relying on Saleor, potentially impacting sales, customer satisfaction, and overall business operations. The number of potential victims is directly proportional to the number of Saleor installations running vulnerable versions.

## Recommendation

*   Upgrade Saleor instances to versions 3.23.0a3, 3.22.47, 3.21.54, or 3.20.118 or later to patch CVE-2026-33756.
*   Deploy the Sigma rule `Detect High Volume of GraphQL Queries` to identify potential exploitation attempts by monitoring the number of GraphQL queries within a single HTTP request in web server logs.
*   Monitor web server logs for abnormally large HTTP POST requests to the `/graphql/` endpoint.
*   Implement rate limiting on the GraphQL endpoint to restrict the number of requests from a single IP address within a defined timeframe.
