---
title: Unauthenticated Denial of Service in Vouch Proxy
slug: 2026-08-vouch-proxy-dos
description: Vouch Proxy contains an unauthenticated heap-allocation vulnerability in its multipart cookie reassembly logic that allows remote attackers to crash the service via a crafted HTTP cookie.
date: "2026-08-20T19:15:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - webserver
vendors:
  - Vouch
products:
  - Vouch Proxy (0.47.2)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single HTTP request with N=10000000000 causes the Go runtime to attempt a ~160 GB heap allocation, triggering a fatal out-of-memory error.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qqff-5854-px68
rules:
  - title: Detect Vouch Proxy Denial of Service Attempt
    description: Detects HTTP requests containing multipart cookie names with extremely large part counts indicative of CVE-like exploitation attempts against Vouch Proxy.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rule to block requests with excessive multipart cookie counts
      owner: SOC
      due: 24h
      evidence: Source provides regex pattern for exploit
  mitigation_plan:
    - priority: immediate
      action: Upgrade Vouch Proxy to current version
      owner: IT Operations
      addresses: Vouch Proxy (0.47.2)
      evidence: Remediation provided in GHSA
---

Vouch Proxy version 0.47.2 is susceptible to an unauthenticated remote denial-of-service vulnerability due to unsafe parsing of multipart cookies. The vulnerability resides in the `pkg/cookie/cookie.go` file within the `Cookie()` function, which reassembles multipart cookies based on names containing the `_NofM` suffix. An attacker can craft a specific HTTP request containing a cookie name with an arbitrarily large integer for the total part count (e.g., `VouchCookie_1of10000000000`). This value is parsed via `strconv.Atoi` and passed directly to `make([]string, numParts)` without bounds checking. Because this logic executes before authentication during the request handling flow, an attacker can trigger an immediate out-of-memory fatal error in the Go runtime, crashing the process. This attack is highly reliable and does not require a valid session.

## Attack Chain

1. Attacker identifies a target server running Vouch Proxy.
2. Attacker crafts a malicious HTTP GET request targeting the `/validate` or `/_external-auth-:id` endpoint.
3. Attacker injects a malicious `Cookie` header into the request, specifically using the format `VouchCookie_1of<Large_Integer>=x`.
4. Vouch Proxy receives the request and, before any authentication, invokes the `JWTCacheHandler`.
5. The `JWTCacheHandler` calls `FindJWT`, which subsequently calls the vulnerable `cookie.Cookie` function.
6. The `cookie.Cookie` function splits the cookie name suffix and parses the attacker-controlled total part count via `strconv.Atoi`.
7. The application executes `make([]string, numParts)` with the unvalidated large integer.
8. The Go runtime attempts to allocate massive amounts of memory, resulting in a fatal out-of-memory crash and immediate denial-of-service.

## Impact

Successful exploitation results in an immediate crash of the Vouch Proxy process. In containerized environments, the service will repeatedly restart, potentially creating a persistent state of denial-of-service if the attacker continues to send the payload. As Vouch Proxy is typically deployed as an authentication gateway, its unavailability can render protected downstream applications unreachable or cause them to fail-open, potentially leading to unauthorized access depending on the reverse-proxy configuration.

## Recommendation

Prioritized actions for detection engineering and security teams:
- Patch Vouch Proxy to the latest version to include input validation for multipart cookie names and strict bounds checking on part counts.
- Apply WAF rules to block or sanitize HTTP requests containing cookie names that exceed reasonable length or format expectations for `_NofM` multipart suffixes.
- Implement monitoring for service crashes and frequent container restarts in the Vouch Proxy environment to identify potential exploitation attempts.
- Deploy the Sigma rule below to detect abnormal cookie header values that indicate exploitation attempts.
