---
title: Varnish HTTP Cache Denial of Service Vulnerability
slug: 2026-09-varnish-cache-dos
description: A vulnerability in Varnish HTTP Cache allows a remote, unauthenticated attacker to trigger a denial of service condition, potentially causing service instability or resource exhaustion.
date: "2026-09-17T13:09:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:haskell:process_library:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*
  - cpe:2.3:a:php:php:*:*:*:*:*:*:*:*
  - cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*
  - cpe:2.3:a:yt-dlp_project:yt-dlp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - webserver
vendors:
  - Varnish Software
products:
  - Varnish HTTP Cache (CVE-2024-3566)
cves:
  - id: CVE-2024-3566
    cvss: 9.8
    epss: 0.06883
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3440
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Varnish HTTP Cache to the vendor-recommended fixed version
      owner: IT Operations
      addresses: CVE-2024-3566
      evidence: Source identifies a DoS vulnerability requiring mitigation.
  gaps:
    - Lack of specific behavioral indicators for detection
---

The BSI has reported a security vulnerability in Varnish HTTP Cache that can be exploited by a remote, unauthenticated attacker to cause a Denial of Service (DoS) condition. The vulnerability, tracked as CVE-2024-3566, impacts the availability of the Varnish service. When successfully exploited, an attacker can crash the Varnish process or exhaust system resources, rendering the caching layer unavailable for downstream clients. This is particularly concerning for environments relying on Varnish to handle high-traffic web requests, as the outage could lead to significant performance degradation or total failure of the backend web applications protected by the cache. Defenders should review current Varnish deployments and ensure they are patched against this identified vulnerability to prevent potential service disruptions.

## Impact

Successful exploitation results in a Denial of Service, which can disrupt business operations by rendering web services inaccessible or severely limited. The impact is primarily on service availability for any sector utilizing Varnish HTTP Cache for high-performance content delivery.

## Recommendation

- Identify all Varnish HTTP Cache installations within the environment using asset management tools.
- Review the Varnish Software security advisories for the specific patch version addressing CVE-2024-3566.
- Apply the vendor-provided patches or updates to all vulnerable Varnish instances.
- Monitor logs for unusual spikes in request traffic or service restarts that may indicate attempted exploitation.
