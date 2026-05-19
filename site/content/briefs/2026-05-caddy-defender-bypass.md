---
title: Caddy Defender Client IP Bypass Vulnerability (CVE-2026-46415)
slug: 2026-05-caddy-defender-bypass
description: Caddy Defender versions before v0.10.1 are vulnerable to a client IP bypass (CVE-2026-46415) when deployed behind a trusted proxy, allowing blocked clients to bypass Defender's IP-based restrictions.
date: "2026-05-19T20:31:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - defender
  - proxy
  - bypass
  - ghsa
vendors:
  - Caddy
products:
  - caddy-defender (< 0.10.1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Proxy Chaining
references:
  - https://github.com/advisories/GHSA-3h23-rrpc-3p87
  - CVE-2026-46415
rules:
  - title: Detect Caddy Defender IP Bypass Attempt
    description: Detects CVE-2026-46415 exploitation — monitors web server logs for requests to Caddy originating from known blocked IP ranges, potentially indicating an attempt to bypass Caddy Defender's IP-based restrictions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Caddy Defender Version < 0.10.1 in User-Agent
    description: Detects potentially vulnerable Caddy Defender versions (prior to v0.10.1) based on the User-Agent header.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

Caddy Defender, a middleware for the Caddy web server, is susceptible to a client IP address bypass vulnerability, identified as CVE-2026-46415, in versions prior to v0.10.1. This flaw arises when Caddy Defender is deployed behind a trusted proxy, CDN, or load balancer. The issue stems from Defender's reliance on `r.RemoteAddr` for evaluating request blocking, which reflects the IP address of the immediate peer (the proxy) rather than the originating client. Consequently, clients within blocked IP ranges can circumvent Defender's intended restrictions by routing their traffic through a trusted proxy whose IP address is not blocked. Organizations using Caddy Defender behind trusted proxies to enforce IP-based access control are particularly vulnerable.

## Attack Chain

1.  A client with a blocked IP address attempts to access a protected resource.
2.  The client's traffic is routed through a trusted proxy, CDN, or load balancer.
3.  The trusted proxy forwards the request to the Caddy web server.
4.  Caddy Defender receives the request and evaluates the IP address for blocking.
5.  Defender incorrectly uses `r.RemoteAddr`, which reflects the trusted proxy's IP address, not the client's.
6.  Since the proxy's IP is not blocked, Defender allows the request to proceed.
7.  The client successfully accesses the protected resource, bypassing the intended IP-based restriction.
8.  The attacker gains unauthorized access to sensitive information or performs actions they should be restricted from.

## Impact

Successful exploitation of this vulnerability (CVE-2026-46415) enables unauthorized access to protected resources by clients that should be blocked based on their IP address. This bypass can lead to data breaches, service disruption, or other malicious activities, depending on the resources protected by Caddy Defender. The severity is high because it directly undermines the intended security functionality of Caddy Defender when deployed behind trusted proxies.

## Recommendation

*   Upgrade Caddy Defender to version v0.10.1 or later to remediate the CVE-2026-46415 vulnerability, as mentioned in the advisory.
*   Deploy the Sigma rule "Detect Caddy Defender IP Bypass Attempt" to identify potential exploitation attempts by monitoring for requests originating from known blocked IP ranges based on web server logs.
*   Until upgrading, enforce equivalent IP blocking at the trusted proxy, CDN, load balancer, or firewall layer as a workaround, as suggested in the advisory.
