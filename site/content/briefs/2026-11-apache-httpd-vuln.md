---
brief_id: brief-2026-11-09-apache-httpd-vuln
event_id: brief-2026-11-09-apache-httpd-vuln
revision: 2
activity_at: "2026-11-14T17:15:23Z"
revision_history:
  - revision: 2
    at: "2026-11-14T17:15:23Z"
    checksum: sha256:ae018ff7d32d97163bbe90a9f4abc688225f1b7bad4700b79a0be236e5fee626
    summary: added coverage for Http Server (< 2.4.64)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - has_poc
      - lastmod
      - poc_references
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GALBARNAHUM-CVE-2025-53020-POC&utm_source=rss&utm_medium=rss
title: 'Apache HTTP Server: Multiple vulnerabilities'
slug: 2026-11-apache-httpd-vuln
description: Multiple undisclosed vulnerabilities have been identified in Apache HTTP Server versions prior to 2.4.70, necessitating an immediate upgrade to the latest version.
date: "2026-11-09T16:12:42Z"
lastmod: "2026-11-14T17:14:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GALBARNAHUM-CVE-2025-53020-POC&utm_source=rss&utm_medium=rss
vendors:
  - Apache
products:
  - HTTP Server
product_versions:
  - product: Http Server
    range: < 2.4.64
  - product: HTTP Server
    range: < 2.4.70
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: By sending batches of requests with thousands of header repetitions, an attacker can rapidly exhaust server memory.
    confidence_band: high
cves:
  - id: CVE-2025-53020
    cvss: 7.5
    epss: 0.04963
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1484/
  - https://downloads.apache.org/httpd/CHANGES_2.4.70
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GALBARNAHUM-CVE-2025-53020-POC&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Apache Http Server to 2.4.64 or later
      owner: IT Operations
      due: 48h
      evidence: Source documentation of CVE-2025-53020 and fixed version 2.4.64
  hunt_leads:
    - lead: Identify HTTP/2 requests with an unusually high count of identical headers or repeated header keys from individual IP sources.
      technique_id: T1499.001
      data_needed:
        - Web server access logs
        - HTTP/2 header field statistics
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The attack leverages HTTP/2's HPACK header compression by first sending an initial request to populate the server's HPACK dynamic table with a long header name.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache HTTP Server to version 2.4.70 or later
      owner: IT Operations
      addresses: Apache HTTP Server (< 2.4.70)
      evidence: Bulletin de sécurité Apache HTTP Server CHANGES_2.4.70 du 06 novembre 2026
    - priority: immediate
      action: Upgrade Apache Http Server to 2.4.64
      owner: IT Operations
      addresses: CVE-2025-53020
      evidence: Source identifies Apache Http Server < 2.4.64 as affected
updates:
  - at: "2026-11-14T17:14:49Z"
    level: L2
    summary: added coverage for Http Server (< 2.4.64)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GALBARNAHUM-CVE-2025-53020-POC&utm_source=rss&utm_medium=rss
---

## Overview

The Apache Software Foundation has released version 2.4.70 of the Apache HTTP Server to address multiple security vulnerabilities. The vendor has not disclosed specific details regarding the vulnerability classes or impact at this time. Administrators are advised to update to the latest version as documented in the official changelog.

## Recommendation

* Inventory all internal and internet-facing assets running Apache HTTP Server.
* Upgrade all instances of Apache HTTP Server to version 2.4.70 or later immediately.
* Monitor the Apache HTTP Server official changelog for future technical disclosures regarding the vulnerabilities addressed in this release.
