---
title: GeoNetwork ACL Bypass in Elasticsearch Search (CVE-2026-46487)
slug: 2026-07-geonetwork-acl-bypass
description: A high-severity authorization bypass vulnerability, CVE-2026-46487, in GeoNetwork's Elasticsearch-backed search API allows unauthenticated attackers to retrieve restricted metadata records by bypassing access control and visibility filters when the request body omits the 'query' field, leading to sensitive information disclosure.
date: "2026-07-03T12:44:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - information-disclosure
  - web-vulnerability
  - elasticsearch
  - geonetwork
  - ghsa
vendors:
  - GeoNetwork
products:
  - GeoNetwork (4.0.0-alpha.1 - 4.0.6-0)
  - GeoNetwork (4.2.0 - 4.2.15)
  - GeoNetwork (4.4.0 - 4.4.10-0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can retrieve the full contents of metadata records that should not be publicly visible.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: A flaw in how that filter-injection step is triggered means it can be skipped under certain conditions, so the affected request reaches Elasticsearch without the intended access restrictions applied.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: allowing an unauthenticated user to retrieve indexed metadata records that should be restricted
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-582q-v28r-7cxr
---

A significant authorization bypass vulnerability (CVE-2026-46487) has been identified in GeoNetwork's search API, affecting all public-facing GeoNetwork 4.x instances from version 4.0.0-alpha.1 through 4.4.10. This flaw lies within the search proxy layer, which is designed to inject access-control and visibility filters into every request before it reaches the underlying Elasticsearch index. However, under specific conditions where the client-supplied search request intentionally omits the 'query' field, this critical filtering step is skipped. As a result, an unauthenticated attacker can retrieve indexed metadata records that should be restricted, including group-specific data, draft records, and information requiring ownership checks, leading to significant information disclosure.

## Attack Chain

1.  An unauthenticated attacker sends a crafted HTTP POST request to a public-facing GeoNetwork instance's Elasticsearch-backed search API endpoint.
2.  The attacker constructs a malformed JSON request body for the Elasticsearch search, intentionally omitting the `query` field, while potentially including other search parameters.
3.  The GeoNetwork search proxy layer, responsible for injecting access-control and visibility filters, fails to apply these restrictions because the `query` field is absent from the request.
4.  The unfiltered request is forwarded to the backend Elasticsearch index without the intended authorization checks for group-based visibility, draft record exclusion, or ownership.
5.  Elasticsearch executes the search query as received and returns all matching metadata records, irrespective of their access control settings.
6.  The unauthenticated attacker receives the full contents of metadata records that should have been restricted, resulting in sensitive information disclosure.

## Impact

This vulnerability (CWE-862: Missing Authorization) leads to unauthorized information disclosure, allowing unauthenticated attackers to access sensitive metadata records. The skipped filter step is responsible for enforcing multiple layers of access control, including group-based record visibility, exclusion of draft records, and ownership verification. Consequently, any public-facing GeoNetwork 4.x instance (versions 4.0.0-alpha.1 through 4.4.10) is vulnerable to an attacker retrieving the full content of metadata that should not be publicly visible, potentially exposing internal project details, draft documents, or data restricted to specific user groups.

## Recommendation

*   Patch affected GeoNetwork instances immediately to a version that addresses CVE-2026-46487.
*   Review web server access logs and GeoNetwork application logs for suspicious HTTP POST requests to the search API that may omit the `query` field, particularly from unknown or untrusted IP addresses.
