---
title: Saleor GraphQL Resource Exhaustion Vulnerability (CVE-2026-35401)
slug: 2026-04-saleor-graphql-exhaustion
description: A remote, unauthenticated attacker can cause resource exhaustion in Saleor e-commerce platforms via maliciously crafted GraphQL API requests, leading to denial of service.
date: "2026-04-08T19:25:23Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

CVE-2026-35401 details a resource exhaustion vulnerability affecting the Saleor e-commerce platform. Present in versions 2.0.0 up to, but not including, 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118, the flaw allows an unauthenticated, remote attacker to exhaust server resources. This is achieved by sending a single API call containing numerous GraphQL mutations or queries, leveraging aliases or chaining techniques. The excessive processing load induced by these malicious requests can lead to a denial-of-service (DoS) condition. Organizations using vulnerable Saleor versions are at risk of service disruption, potentially impacting business operations and revenue. Mitigation involves upgrading to the patched versions: 3.23.0a3, 3.22.47, 3.21.54, or 3.20.118.

## Attack Chain

1.  The attacker identifies a Saleor e-commerce platform running a vulnerable version (2.0.0 to before 3.23.0a3, 3.22.47, 3.21.54, and 3.20.118).
2.  The attacker crafts a malicious GraphQL query or mutation containing numerous aliased or chained operations. This is done to maximize server-side processing load.
3.  The attacker sends the crafted GraphQL request to the Saleor platform's API endpoint, typically `/graphql/`.
4.  The Saleor server attempts to process all the queries/mutations within the single request.
5.  The server resources (CPU, memory, database connections) are rapidly consumed by the excessive processing demand.
6.  The server becomes slow and unresponsive, potentially timing out for legitimate user requests.
7.  The Saleor e-commerce platform experiences a denial-of-service condition, disrupting service for legitimate customers.
8.  The attacker may repeat this process to maintain the denial-of-service state, further impacting business operations.

## Impact

Successful exploitation of CVE-2026-35401 leads to resource exhaustion on the Saleor e-commerce platform, resulting in a denial-of-service condition. This disruption can impact online sales, customer experience, and brand reputation. The number of affected systems depends on the prevalence of vulnerable Saleor installations. While the exact number of victims is unknown, any e-commerce business using an unpatched version is susceptible to service outages. Prolonged or repeated attacks can lead to significant financial losses and damage to business operations.

## Recommendation

*   Immediately upgrade Saleor e-commerce platforms to versions 3.23.0a3, 3.22.47, 3.21.54, or 3.20.118 to patch CVE-2026-35401.
*   Implement rate limiting on the `/graphql/` API endpoint to mitigate the impact of excessive requests.
*   Deploy the Sigma rule `Detect Suspicious GraphQL Volume` to identify potential exploitation attempts based on request patterns.
