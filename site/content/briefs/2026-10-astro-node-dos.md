---
title: Denial of Service in Astro Node Adapter via Malformed Host Header
slug: 2026-10-astro-node-dos
description: A vulnerability in the @astrojs/node adapter, identified as CVE-2026-102984, allows remote attackers to trigger a process crash by sending HTTP requests with malformed Host headers.
date: "2026-10-01T04:21:27Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:astro:astrojs_node:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - webserver
  - vulnerability
vendors:
  - Astro
products:
  - '@astrojs/node (<= 11.1.2)'
cves:
  - id: CVE-2026-102984
references:
  - https://github.com/advisories/GHSA-qh8j-hqjv-7m4x
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-102984
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade @astrojs/node to 11.1.3
      owner: IT Operations
      due: 48h
      evidence: Source advisory states 11.1.3 contains the fix.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Reverse Proxy to block malformed Host headers
      owner: Network Security
      addresses: CVE-2026-102984
      evidence: Source states that deployments terminating malformed headers at proxies are not reachable.
---

A vulnerability (CVE-2026-102984) exists in the `@astrojs/node` adapter (versions 11.1.2 and earlier) where improper validation of the `Host` header can lead to a denial-of-service condition. An attacker can craft a request with an invalid port specification within the `Host` header, such as `example.com:65536` or `example.com:8080:8080`. When the adapter attempts to process these requests, the logic fails to correctly generate a request URL and enters a recursive failure state. This results in an uncaught `TypeError: Invalid URL` exception. If the server is configured with `staticHeaders: true`, this exception remains unhandled, causing the entire Node.js process to terminate. This vulnerability is limited to availability disruption and does not facilitate data exfiltration or remote code execution.

## Impact

The vulnerability impacts applications using the `@astrojs/node` adapter, specifically those configured with the `staticHeaders: true` option, as these are susceptible to process termination. Successfully sending a crafted request to such an endpoint will crash the server, causing service downtime. Applications using the default `standalone` configuration will experience a `500 Internal Server Error` but will remain running. The attack surface is dependent on whether upstream infrastructure, such as CDNs or reverse proxies, filters malformed `Host` headers before they reach the Astro origin.

## Recommendation

- Upgrade to `@astrojs/node` version 11.1.3 or later immediately to incorporate the required host validation logic.
- Implement strict request validation at the reverse proxy or CDN layer to block HTTP requests containing malformed `Host` headers or multiple port specifications.
- Audit existing deployments to identify configurations utilizing `staticHeaders: true`, as these are at higher risk of process termination.
