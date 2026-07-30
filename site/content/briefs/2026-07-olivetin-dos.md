---
title: OliveTin Unauthenticated OAuth2 Memory Exhaustion
slug: 2026-07-olivetin-dos
description: An unauthenticated attacker can trigger a denial-of-service in OliveTin by flooding the OAuth2 login endpoint, causing unbounded memory growth due to the lack of expiration for stored login states.
date: "2026-07-30T15:30:25Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - OliveTin
products:
  - OliveTin
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can send millions of requests to /oauth/login to fill the map with state entries, exhausting server memory and causing a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-67437
    cvss: 7.5
    epss: 0.00354
references:
  - https://github.com/advisories/GHSA-xpxj-f2fm-rqch
  - CVE-2026-67437
rules:
  - title: Detect Excessive OAuth2 Login Requests
    description: Detects potential DoS attempts against OliveTin by monitoring for high frequencies of requests to the /oauth/login endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 1
---

OliveTin contains a vulnerability (CVE-2026-67437) where the application's OAuth2 login handler stores per-login state in an in-memory map (`registeredStates`) that grows without bounds. Because the application fails to implement time-to-live (TTL) expiry, size limits, or cleanup mechanisms for these map entries, an unauthenticated attacker can trigger a denial-of-service (DoS) condition. By sending a high volume of requests to the `/oauth/login` endpoint, an attacker forces the application to allocate memory for each new state entry, eventually leading to OOM (Out of Memory) kills or severe service degradation. This vulnerability is distinct from previous concurrent map access issues, as it persists even when synchronization primitives are correctly implemented. Defenders should note that memory is not reclaimed after the attack stops, requiring a service restart to restore normal operation.

## Attack Chain

1. Attacker performs reconnaissance to confirm the target OliveTin instance has OAuth2 providers configured.
2. Attacker identifies the publicly accessible `/oauth/login` endpoint on the target instance.
3. Attacker initiates a flood of HTTP GET requests to `/oauth/login` with the `provider` parameter set.
4. The OliveTin `HandleOAuthLogin` function executes, generating a new `oauth2State` entry.
5. The application adds the new `oauth2State` to the `registeredStates` in-memory map.
6. The application performs a 302 redirect back to the attacker, but the state object remains permanently in memory.
7. The process continues until system memory is exhausted, resulting in service crash or unresponsive application state.

## Impact

Successful exploitation results in a persistent denial-of-service for all users of the OliveTin instance. Because the leaked memory is not recovered until a process restart, even intermittent attacks can lead to cumulative degradation. The vulnerability affects all deployments configured with one or more OAuth2 providers and provides an unauthenticated vector for service disruption.

## Recommendation

1. Upgrade to the patched version of OliveTin (minimum version `0.0.0-20260708075951-ec114e95d297`) immediately to incorporate state cleanup mechanisms.
2. Implement rate limiting on the `/oauth/login` endpoint at the web application firewall or reverse proxy layer to mitigate high-frequency request floods.
3. Deploy the Sigma rule below to monitor for anomalous request volumes to the OAuth2 login endpoint.
4. Monitor application memory usage metrics (e.g., via Docker stats or container orchestration monitoring) for signs of anomalous, monotonic growth associated with `olivetin-instance`.
