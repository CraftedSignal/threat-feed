---
title: Saleor GraphQL Resource Exhaustion Vulnerability (CVE-2026-35401)
slug: 2026-04-saleor-graphql-exhaustion
description: A remote, unauthenticated attacker can cause resource exhaustion in Saleor e-commerce platforms via maliciously crafted GraphQL API requests, leading to denial of service.
date: "2026-04-08T19:25:23Z"
severities:
  - medium
tags:
  - cve-2026-35401
  - graphql
  - resource-exhaustion
  - denial-of-service
  - saleor
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-35401
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35401
  - https://github.com/saleor/saleor/security/advisories/GHSA-gqqv-xwx3-jj4h
rules:
  - title: Detect Suspicious GraphQL Volume
    description: Detects abnormally high volume of GraphQL requests to the /graphql/ endpoint, which may indicate a resource exhaustion attack attempt.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Long GraphQL Queries
    description: Detects GraphQL queries with unusually long URLs, potentially indicating aliasing or chaining abuse.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-35401 details a resource exhaustion vulnerability affecting the Saleor e-commerce platform. Present in versions 2.0.0 up to, but not including, 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118, the flaw allows an unauthenticated, remote attacker to exhaust server resources. This is achieved by sending a single API call containing numerous GraphQL mutations or queries, leveraging aliases or chaining techniques. The excessive processing load induced by these malicious requests can lead to a…
