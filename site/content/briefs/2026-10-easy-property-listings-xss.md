---
brief_id: brief-2026-10-29-easy-property-listings-xss
event_id: brief-2026-10-29-easy-property-listings-xss
revision: 2
activity_at: "2026-11-07T14:10:22Z"
revision_history:
  - revision: 2
    at: "2026-11-07T14:10:22Z"
    checksum: sha256:5d69b55cbbed8585ca90ea05989672e841188869c81a293138a67c04975035a6
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=D53CD4C5-93AD-5113-BF5F-0B69D2F15205&utm_source=rss&utm_medium=rss
title: 'Easy Property Listings: Unauthenticated Cross-Site Scripting (CVE-2026-61989)'
slug: 2026-10-easy-property-listings-xss
description: An unauthenticated Cross-Site Scripting (XSS) vulnerability in Easy Property Listings versions 3.5.25 and earlier allows attackers to inject malicious scripts into web pages viewed by other users.
date: "2026-10-29T17:40:05Z"
lastmod: "2026-11-07T14:08:14Z"
type: advisory
claim_state: <nil>
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source validated; requires local environment verification.
cpes:
  - cpe:2.3:a:easy_property_listings:easy_property_listings:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=D53CD4C5-93AD-5113-BF5F-0B69D2F15205&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - xss
  - vulnerability
vendors:
  - Easy Property Listings
products:
  - Easy Property Listings (<= 3.5.25)
cves:
  - id: CVE-2026-61989
    cvss: 7.1
    epss: 0.00175
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61989
  - https://sploitus.com/exploit?id=D53CD4C5-93AD-5113-BF5F-0B69D2F15205&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  hunt_leads:
    - lead: Hunt for web request logs containing suspicious script-like payloads in parameters
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: XSS vulnerabilities are typically exploited via crafted input parameters in HTTP requests.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Easy Property Listings to a version beyond 3.5.25
      owner: IT Operations
      addresses: CVE-2026-61989
      evidence: Source material indicates vulnerability exists in 3.5.25 and earlier.
updates:
  - at: "2026-11-07T14:08:14Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=D53CD4C5-93AD-5113-BF5F-0B69D2F15205&utm_source=rss&utm_medium=rss
---

CVE-2026-61989 describes an unauthenticated Cross-Site Scripting (XSS) vulnerability affecting Easy Property Listings versions 3.5.25 and earlier. The vulnerability allows an attacker to inject arbitrary client-side scripts into web pages, which are then executed within the context of other users' sessions. This can lead to unauthorized actions performed on behalf of the victim or session hijacking.

## Impact

Successful exploitation allows for the execution of unauthorized scripts in the context of a victim's session, potentially leading to unauthorized actions or session hijacking.

## Recommendation

Update the Easy Property Listings plugin to a version released after 3.5.25 to remediate this vulnerability. Implement a Web Application Firewall (WAF) to filter malicious input patterns associated with XSS attacks for the affected web application.
