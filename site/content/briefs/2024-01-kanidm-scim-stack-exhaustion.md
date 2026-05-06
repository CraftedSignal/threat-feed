---
title: Kanidm SCIM Filter Stack Exhaustion Vulnerability
slug: 2024-01-kanidm-scim-stack-exhaustion
description: An unauthenticated GET request with deeply nested parentheses in the SCIM filter parameter can cause stack exhaustion and process termination in Kanidm, leading to denial of service.
date: "2026-05-06T23:38:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - scim
  - stack-overflow
vendors:
  - kanidm
products:
  - kanidm_proto (<= 1.9.2)
  - scim_proto (<= 1.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-r5fr-9gmv-jggh
rules:
  - title: Detect Suspiciously Long SCIM Filter Queries
    description: Detects abnormally long SCIM filter queries which may indicate a stack exhaustion attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple SCIM Requests from Same IP in Short Period
    description: Detects a high volume of requests to SCIM endpoints from the same source IP, potentially indicating a DoS attack.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kanidm versions 1.7.0 through 1.9.2 are vulnerable to a stack exhaustion issue due to unbounded recursion in the SCIM filter parser. An attacker can send an unauthenticated GET request to any `/scim/v1/...` endpoint, including `/scim/v1/Application`, `/scim/v1/Entry/{id}`, etc., with a `filter` query parameter containing thousands of nested parentheses. This input drives the recursive-descent PEG parser beyond the worker thread's stack limit. The vulnerability exists within the axum's `Query<ScimEntryGetQuery>` extractor, before any authentication or authorization checks. The resulting stack overflow triggers `std::process::abort()`, causing the entire `kanidmd` process to terminate, affecting all services relying on the IDM. This can be exploited to cause a denial-of-service condition.

## Attack Chain

1.  The attacker crafts a malicious GET request targeting a SCIM endpoint, such as `/scim/v1/Application?filter=(...(a+pr)...)`.
2.  The crafted request contains a `filter` query parameter with thousands of nested parentheses, exceeding the stack limit.
3.  The request is received by the Kanidm server.
4.  Axum's `Query<ScimEntryGetQuery>` extractor attempts to parse the `filter` parameter using the SCIM filter parser (`scimfilter::parse`).
5.  The SCIM filter parser recursively processes the nested parentheses without a depth bound, consuming stack space.
6.  The recursive parsing exceeds the worker thread's stack guard page, leading to a stack overflow.
7.  Rust's stack overflow handler triggers `std::process::abort()`, terminating the `kanidmd` process.
8.  The entire Kanidm service becomes unavailable, disrupting authentication, authorization, and other IDM functions.

## Impact

Successful exploitation leads to a process-wide denial of service. The `kanidmd` process terminates, affecting all in-flight HTTP requests, OAuth2/OIDC sessions, LDAP binds, and the web UI. The vulnerability is unauthenticated and easily repeatable, allowing an attacker to hold the service down indefinitely. A single 12KB GET request is sufficient to crash the service.

## Recommendation

*   Apply the patch or upgrade to a version of `kanidm_proto` and `scim_proto` greater than 1.9.2 to resolve the unbounded recursion in the SCIM filter parser.
*   Implement rate limiting on SCIM endpoints to mitigate the impact of repeated exploitation attempts.
*   Deploy the following Sigma rule to detect potentially malicious SCIM filter requests based on URL length.
*   Consider limiting the maximum size of request headers accepted by the web server to prevent large `filter` parameters.
