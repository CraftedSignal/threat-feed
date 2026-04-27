---
title: Saleor GraphQL Batch Query Resource Exhaustion Vulnerability (CVE-2026-33756)
slug: 2026-04-saleor-resource-exhaustion
description: Unauthenticated attackers can exploit a resource exhaustion vulnerability (CVE-2026-33756) in Saleor e-commerce platform versions before 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118 by sending a single HTTP request with a large number of GraphQL operations, bypassing query complexity limits and exhausting server resources.
date: "2026-04-09T12:00:00Z"
severities:
  - medium
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

Saleor, an e-commerce platform, is susceptible to a resource exhaustion vulnerability affecting versions 2.0.0 prior to 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118. This vulnerability stems from the platform's support for query batching, where multiple GraphQL operations can be submitted in a single HTTP request as a JSON array. The absence of an upper limit on the number of operations within a single request allows unauthenticated attackers to bypass per-query complexity limits. By sending a…
