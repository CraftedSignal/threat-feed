---
brief_id: brief-2026-10-31-nextjs-smuggling
event_id: brief-2026-10-31-nextjs-smuggling
revision: 1
activity_at: "2026-10-31T04:07:07Z"
title: Vercel Next.js HTTP Request Smuggling (CVE-2026-29057)
slug: 2026-10-nextjs-smuggling
description: CVE-2026-29057 is an HTTP request smuggling vulnerability in Next.js allowing attackers to smuggle secondary requests to internal backends via chunked transfer-encoding desynchronization.
date: "2026-10-31T04:07:07Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*
  - cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*
tags:
  - cve-2026-29057
  - request-smuggling
  - web-vulnerability
  - vercel
vendors:
  - Vercel
products:
  - Next.js (< 15.5.13, 16.1.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Request smuggling via Transfer-Encoding: chunked on a rewritten route, allowing an attacker to smuggle a second request to an internal backend.'
    confidence_band: high
cves:
  - id: CVE-2026-29057
    cvss: 6.5
    epss: 0.00453
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-ggv3-7p47-pfv8
  - https://github.com/vercel/next.js/commit/dc98c04f376c6a1df76ec3e0a2d07edf4abdabd6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29057
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LEARNERXUAN-CVE-2026-29057-POC&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Next.js to 15.5.13 or 16.1.7
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions prior to 15.5.13 and 16.1.7
  hunt_leads:
    - lead: 'Inspect web server and WAF logs for HTTP requests containing Transfer-Encoding: chunked that also contain suspicious internal route patterns in the request body'
      technique_id: T1190
      data_needed:
        - Raw HTTP request logs including full headers and bodies
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'Request smuggling via Transfer-Encoding: chunked on a rewritten route allows smuggling requests to internal backend.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade Next.js to 15.5.13 or 16.1.7
      owner: IT Operations
      addresses: CVE-2026-29057
      evidence: Vulnerable versions are < 15.5.13 and 16.1.7
---

CVE-2026-29057 describes an HTTP request smuggling vulnerability in Vercel Next.js versions prior to 15.5.13 and 16.1.7. The issue arises from the desynchronization of shared HTTP connections when processing chunked `Transfer-Encoding` headers. An attacker can use a crafted request to cause the application's internal frontend/proxy component to misinterpret request boundaries, leading it to forward a smuggled request to an internal backend service.

## Attack Chain
1. Attacker sends a primary request to a public endpoint using `Transfer-Encoding: chunked`.
2. The primary request body contains the serialized bytes of a secondary, unauthorized request (e.g., `GET /secret`).
3. The vulnerable frontend component fails to properly calculate or reconcile the length of the chunked message.
4. The frontend component strips or modifies headers but leaves the smuggled payload in the buffered stream.
5. The internal intermediary interprets the remaining bytes as a second, distinct HTTP request.
6. The internal backend processes both the initial and the smuggled requests sequentially.

## Impact
The vulnerability allows for unauthorized access to internal backend routes or administrative endpoints that are not intended to be exposed to public traffic.

## Recommendation
- Upgrade Vercel Next.js to version 15.5.13, 16.1.7, or later immediately.
- Review web access logs for anomalous `Transfer-Encoding: chunked` requests that contain embedded HTTP methods or internal path patterns.
- Apply strict request validation at the edge/WAF to normalize or reject malformed `Transfer-Encoding` headers before they reach the Next.js application.
