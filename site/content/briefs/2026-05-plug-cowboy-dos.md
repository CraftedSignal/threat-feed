---
title: Plug.Cowboy HTTP/2 Atom Table Exhaustion DoS
slug: 2026-05-plug-cowboy-dos
description: An unauthenticated remote denial-of-service vulnerability in Plug.Cowboy allows attackers to exhaust the BEAM atom table via HTTP/2 requests, crashing the Erlang VM.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - http2
  - atom-exhaustion
vendors:
  - Erlang
products:
  - plug_cowboy (2.0.0 < 2.8.1)
  - Phoenix
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-32688
    epss: 0.00131
references:
  - https://github.com/advisories/GHSA-q8x4-x7mp-5vg2
rules:
  - title: Detect Excessive HTTP/2 Header Fields
    description: Detects a high number of unique header fields in HTTP/2 requests, which may indicate an atom table exhaustion attempt.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP/2 Requests with Many Scheme Headers
    description: Detects HTTP/2 requests containing an excessive number of `:scheme` headers, potentially indicating an attempt to exploit CVE-2026-32688.
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

A denial-of-service vulnerability exists in Plug.Cowboy versions prior to 2.8.1. This vulnerability allows an unauthenticated remote attacker to crash an Erlang VM by exhausting the BEAM atom table. The attack is performed by sending malicious HTTP/2 requests to a Plug.Cowboy listener. Successful exploitation leads to a complete denial of service, as the entire Erlang VM terminates. Phoenix applications using plug_cowboy with HTTP/2 enabled are also affected. Projects utilizing alternative HTTP adapters like Bandit are not susceptible to this specific vulnerability. The issue was identified and responsibly disclosed by Peter Ullrich.

## Attack Chain

1. An attacker identifies a target server running Plug.Cowboy with HTTP/2 enabled.
2. The attacker crafts a series of HTTP/2 requests with a malformed or excessive number of `:scheme` header fields or other header fields that contribute to atom creation.
3. The attacker sends the crafted HTTP/2 requests to the target server.
4. Plug.Cowboy processes the HTTP/2 requests, allocating a new atom for each unique header field value received.
5. The attacker continues sending malicious requests, rapidly increasing the number of atoms in the Erlang VM.
6. The BEAM atom table reaches its maximum capacity due to the attacker's crafted requests.
7. The Erlang VM crashes due to atom exhaustion, leading to a denial-of-service condition.
8. The application using Plug.Cowboy becomes unavailable, disrupting service.

## Impact

Successful exploitation of this vulnerability results in a complete denial-of-service condition. All applications running on the affected Erlang VM will crash, impacting availability and potentially causing data loss. The number of victims depends on the deployment of Plug.Cowboy and Phoenix applications using HTTP/2. The vulnerability impacts any organization utilizing the affected software, potentially disrupting critical services.

## Recommendation

- Upgrade to `plug_cowboy` version 2.8.1 or later to patch CVE-2026-32688.
- If upgrading is not immediately feasible, consider disabling HTTP/2 on affected Plug.Cowboy instances as a temporary mitigation.
- Deploy a web application firewall (WAF) to filter HTTP/2 requests with suspicious header patterns, mitigating potential exploitation attempts.
- Monitor webserver logs for excessive or malformed HTTP/2 requests, which might indicate an attempted atom table exhaustion attack.
