---
title: Denial of Service Vulnerability in SmallRye GraphQL
slug: 2026-08-smallrye-graphql-dos
description: An unauthenticated remote attacker can cause a denial of service in SmallRye GraphQL by exploiting improper BigInteger scalar coercion to trigger resource exhaustion.
date: "2026-08-31T15:58:02Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:smallrye:graphql:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - graphql
vendors:
  - SmallRye
products:
  - GraphQL
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can exploit this by sending a GraphQL query containing a large exponent float literal... leading to CPU exhaustion or an OutOfMemoryError.
    confidence_band: high
cves:
  - id: CVE-2026-76763
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76763
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all services utilizing SmallRye GraphQL
      owner: IT Operations
      due: 48h
      evidence: Source confirms SmallRye GraphQL contains the flaw
  mitigation_plan:
    - priority: immediate
      action: Upgrade SmallRye GraphQL to the latest patched release
      owner: IT Operations
      addresses: CVE-2026-76763
      evidence: Vulnerability in number scalar coercion for BigInteger
---

A high-severity vulnerability (CVE-2026-76763) has been identified in the SmallRye GraphQL implementation. The flaw exists within the number scalar coercion logic for BigInteger objects, which fails to adequately validate the magnitude of float or string inputs provided during query processing. An unauthenticated remote attacker can exploit this weakness by crafting a malicious GraphQL query containing an exceptionally large exponent float literal. When processed by the application, this input forces the system to allocate massive BigInteger objects, leading to uncontrolled CPU consumption or an OutOfMemoryError (OOME). This exploitation effectively crashes the service or degrades performance to the point of a denial of service, impacting availability for all users of the affected GraphQL endpoint.

## Impact

Successful exploitation of this vulnerability results in a denial of service for any application utilizing the vulnerable SmallRye GraphQL library. This can lead to service outages and instability, potentially affecting all sectors that rely on this library for GraphQL API operations. Given the ease of delivery via a standard GraphQL query, the impact on availability is significant for internet-facing APIs.

## Recommendation

Prioritized actions for security and operations teams:

- Identify all internal and external-facing applications utilizing the SmallRye GraphQL library.
- Monitor application logs and infrastructure metrics for spikes in CPU usage or frequent OutOfMemoryError exceptions following incoming GraphQL requests.
- Review vendor release notes for the patched version of SmallRye GraphQL and perform a rolling update across the environment.
- Implement request-size validation and rate limiting on GraphQL endpoints to prevent the processing of abnormally large or malformed query payloads.
