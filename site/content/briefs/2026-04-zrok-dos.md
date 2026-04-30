---
title: zrok Unauthenticated Denial-of-Service Vulnerability
slug: 2026-04-zrok-dos
description: An unauthenticated attacker can cause a denial-of-service (DoS) in zrok by sending a crafted HTTP request with a large cookie chunk count to an OAuth-protected proxy share, triggering unbounded memory allocation and leading to process termination.
date: "2026-04-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dos
  - vulnerability
  - zrok
  - CVE-2026-40303
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-cpf9-ph2j-ccr9
rules:
  - title: Detect Suspicious Cookie Header Size
    description: Detects HTTP requests with abnormally large Cookie header sizes, potentially indicating a DoS attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple 500 Errors From Zrok Proxy
    description: Detects multiple 500 errors originating from a Zrok proxy server within a short time frame, potentially indicating a DoS condition.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in zrok versions 1.1.11 and earlier, as well as versions 2.0.0 and earlier, due to unbounded memory allocation in the `GetSessionCookie` function. This function, located in `endpoints/oauthCookies.go`, parses an attacker-supplied cookie chunk count and calls `make([]string, count)` without any upper bound before token validation. Since this function is invoked on every request to an OAuth-protected proxy share, an unauthenticated remote attacker can send a single HTTP request with a crafted Cookie header to trigger gigabyte-scale heap allocations. This can lead to process-level out-of-memory (OOM) termination or repeated goroutine panics, effectively disabling the proxy server and impacting all users of the affected shares. Both `publicProxy` and `dynamicProxy` are affected. This vulnerability is identified as CVE-2026-40303.

## Attack Chain

1. The attacker identifies a zrok proxy server running a vulnerable version (<= 1.1.11 or < 2.0.1).
2. The attacker discovers an OAuth-protected proxy share. The cookie name is publicly derivable from any OAuth redirect.
3. The attacker crafts an HTTP request with a Cookie header.
4. The Cookie header is specifically crafted to include a large chunk count.
5. The `endpoints.GetSessionCookie` function in `endpoints/oauthCookies.go` is called to parse the cookie.
6. Inside `GetSessionCookie`, `make([]string, count)` is called with the attacker-controlled count from the cookie, resulting in unbounded memory allocation.
7. The excessive memory allocation leads to either OOM termination of the zrok proxy process, or repeated goroutine panics.
8. The zrok proxy server becomes unavailable, impacting all users of all shares it serves.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. The zrok proxy server becomes unavailable, preventing legitimate users from accessing proxied resources. The number of affected users depends on the deployment size, but all users of any shares served by the affected proxy instance will be impacted until the service restarts or the vulnerability is patched. The targeted sector is any organization utilizing zrok for secure tunneling and sharing of resources.

## Recommendation

*   Apply the patch for CVE-2026-40303 by upgrading to zrok version 1.1.12 or later, or 2.0.1 or later.
*   Implement rate limiting on incoming HTTP requests to the zrok proxy to mitigate the impact of potential exploitation.
*   Deploy the Sigma rule `Detect Suspicious Cookie Header Size` to identify requests with abnormally large cookie sizes.
*   Monitor zrok proxy server resource utilization (CPU, memory) for unexpected spikes, which could indicate exploitation attempts.
