---
title: Plug Framework Quadratic Complexity Denial of Service via CVE-2026-54892
slug: 2026-09-plug-dos
description: An unauthenticated remote attacker can trigger a denial-of-service condition in Elixir applications using the Plug framework by submitting URL-encoded payloads with deeply nested brackets that consume excessive CPU cycles on the BEAM scheduler.
date: "2026-09-23T19:59:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - Plug (>= 1.15.0, < 1.15.5)
  - Plug (>= 1.16.0, < 1.16.4)
  - Plug (>= 1.17.0, < 1.17.2)
  - Plug (>= 1.18.0, < 1.18.3)
  - Plug (>= 1.19.0, < 1.19.3)
cves:
  - id: CVE-2026-54892
    epss: 0.00949
references:
  - https://github.com/advisories/GHSA-j43x-5hjq-rgxf
  - https://github.com/elixir-plug/plug/commit/712b875d3442c765d8d37e546ffd5ad9f8afcc55
  - https://github.com/elixir-plug/plug/commit/b4aa8a0665ce2726a6d5af44467fb4f59595b107
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Plug to 1.15.5 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-54892 remediation requires version update.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict maximum allowed body length in Plug.Parsers configuration to reduce surface area for large payloads.
      owner: IT Operations
      addresses: CVE-2026-54892
      evidence: Source notes Plug.Parsers body limit allows payloads that trigger the quadratic complexity issue.
---

The Elixir Plug library (specifically the `Plug.Conn.Query` module) contains a performance vulnerability stemming from quadratic-time complexity during the decoding of nested query or body parameters. When parsing URL-encoded keys with deep bracket nesting (e.g., `a[a][a]...=1`), the library performs repetitive map operations and prefix hashing that scale at O(N^2) relative to the nesting depth.

Because the `Plug.Parsers` component accepts `application/x-www-form-urlencoded` payloads up to the configured global body limit (defaulting to 20 MB), an attacker can inject hundreds of thousands of nesting levels in a single request. This behavior pins a BEAM scheduler for minutes. By sending a small number of concurrent requests, an attacker can exhaust all available schedulers, rendering the entire Elixir or Phoenix application unresponsive. The vulnerability affects multiple versions across the 1.15.x to 1.19.x branches. Defenders should prioritize updating to the patched versions provided in the security advisory.

## Attack Chain

1. Attacker crafts an HTTP POST request targeting an endpoint handled by the Plug framework.
2. Attacker sets the `Content-Type` header to `application/x-www-form-urlencoded`.
3. Attacker populates the request body with a parameter string featuring extreme bracket nesting (e.g., millions of `[a]` segments).
4. The Plug `Plug.Parsers.URLENCODED` parser accepts the payload as a valid body within the default 20MB limit.
5. `Plug.Conn.Query.decode/4` initiates recursive parsing of the nested query keys.
6. The `Plug.Conn.Query.split_keys/6` and `insert_keys/3` functions perform quadratic operations while hashing the growing key prefixes.
7. The BEAM scheduler becomes pinned by the CPU-intensive decoding process.
8. Concurrent requests exhaust the scheduler pool, resulting in application-wide denial of service.

## Impact

Successful exploitation allows an unauthenticated remote attacker to cause a complete denial of service for any internet-facing web application built on the Plug framework (including Phoenix). No specialized knowledge of the target application structure or authentication is required. A single low-bandwidth sender can stall application processing, affecting availability for all legitimate users.

## Recommendation

* Upgrade the Plug library immediately to the patched versions: 1.15.5, 1.16.4, 1.17.2, 1.18.3, or 1.19.3.
* Audit application configurations for `Plug.Parsers` to restrict `length` and `query_length` limits to the minimum necessary for expected traffic.
* Deploy web application firewall (WAF) rules to detect and drop requests with excessive bracket nesting depth in query strings or POST bodies.
* Monitor application performance metrics for sustained, high CPU utilization on BEAM schedulers initiated by short-duration, high-payload requests.
