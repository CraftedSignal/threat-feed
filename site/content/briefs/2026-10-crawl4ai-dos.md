---
brief_id: brief-2026-10-29-crawl4ai-dos
event_id: brief-2026-10-29-crawl4ai-dos
revision: 1
activity_at: "2026-10-29T17:33:11Z"
title: 'Crawl4AI: Denial of service in Docker API server (CVE-2026-119119)'
slug: 2026-10-crawl4ai-dos
description: Crawl4AI versions prior to 0.9.5 are vulnerable to a denial-of-service attack due to improper validation of delay parameters in untrusted CrawlerRunConfig requests, allowing unauthenticated attackers to exhaust browser page resources.
date: "2026-10-29T17:33:11Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:crawl4ai:crawl4ai:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - input-validation
  - web-api
vendors:
  - Crawl4AI
products:
  - Crawl4AI (< 0.9.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated attacker can exploit this by submitting crafted requests to the /crawl or /crawl/stream endpoints with excessively large delay values, causing resource exhaustion in the browser page pool and preventing legitimate crawling operations.
    confidence_band: high
cves:
  - id: CVE-2026-119119
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119119
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Crawl4AI instances to 0.9.5 or later.
      owner: IT Operations
      due: 48h
      evidence: Crawl4AI before 0.9.5 contains a denial of service vulnerability.
  hunt_leads:
    - lead: Identify HTTP POST requests to /crawl or /crawl/stream with atypically high values for delay_before_return_html, mean_delay, or max_range.
      technique_id: T1498
      data_needed:
        - Web server access logs or API gateway request logs containing JSON request bodies.
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated attackers can send huge values to /crawl or /crawl/stream to hold browser pages or stall the rate limiter.
  mitigation_plan:
    - priority: immediate
      action: Apply input validation or rate limiting at the WAF/API Gateway layer for /crawl and /crawl/stream.
      owner: IT Operations
      addresses: CVE-2026-119119
      evidence: Vulnerability in Docker API server where _clamp_untrusted() fails to cap delay fields.
---

Crawl4AI versions before 0.9.5 contain a denial of service vulnerability in the Docker API server component. The function `_clamp_untrusted()` fails to cap the `delay_before_return_html`, `mean_delay`, and `max_range` fields within untrusted `CrawlerRunConfig` request bodies. By submitting specially crafted HTTP requests to the `/crawl` or `/crawl/stream` endpoints, an unauthenticated attacker can supply excessively large values for these parameters. This forces the application to hold browser pages or stall the rate limiter indefinitely, leading to resource exhaustion of the browser page pool and preventing legitimate crawling operations.

## Impact
Successful exploitation allows an unauthenticated attacker to render the Crawl4AI service unavailable for legitimate users by exhausting the browser page pool.

## Recommendation
- Upgrade Crawl4AI to version 0.9.5 or later to resolve the improper input validation in the Docker API server.
- Implement request rate limiting and input validation at the edge (e.g., WAF or API Gateway) for the `/crawl` and `/crawl/stream` endpoints if an immediate upgrade is not possible.
- Monitor logs for HTTP POST requests to `/crawl` or `/crawl/stream` containing unusually large values in the specified JSON fields.
