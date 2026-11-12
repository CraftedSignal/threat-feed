---
brief_id: brief-2026-11-04-google-chrome-update
event_id: brief-2026-11-04-google-chrome-update
revision: 5
activity_at: "2026-11-12T23:02:58Z"
revision_history:
  - revision: 2
    at: "2026-11-05T10:39:49Z"
    checksum: sha256:1a2dc96599bad019f9b2487d62feb3c8a9e560727e28bbb09d218d3381ec9468
    summary: added CVE-2026-91732
    changed_fields:
      - affected_products
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-91732
  - revision: 3
    at: "2026-11-10T16:31:37Z"
    checksum: sha256:d9d835f81f10f1bd8efadd4ed2dce56aac3e07c42f2e35b2c2bb832315f51027
    summary: new product
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4417
  - revision: 4
    at: "2026-11-12T16:23:46Z"
    checksum: sha256:4cc743460c905a299ff646f3367fca1d37c39711a31051710face4ea2d87537a
    summary: new product
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4518
  - revision: 5
    at: "2026-11-12T23:02:58Z"
    checksum: sha256:6e8d99d65938ee37300a1d56445057d57c09082a3ae17301f83a9965e73241ae
    summary: added coverage for Chrome (< 157.0.8103.78)
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/google-security-advisory-av26-1157
title: 'Google Chrome: Multiple Vulnerabilities'
slug: 2026-11-google-chrome-update
description: Google has released a security update for the Stable Channel of Chrome for Desktop to address unspecified vulnerabilities in versions prior to 157.0.8103.38.
date: "2026-11-04T21:11:46Z"
lastmod: "2026-11-12T23:00:39Z"
type: advisory
claim_state: <nil>
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - informational
  - browser
  - patch-management
  - product-news
vendors:
  - Google
products:
  - Chrome
  - Chrome (< 153.0.8010.47, < 157.0.8103.38)
  - Chrome for Desktop
product_versions:
  - product: Chrome
    range: < 153.0.8010.47
  - product: Chrome
    range: < 157.0.8103.78
  - product: Chrome for Desktop
    range: < 157.0.8103.38
affected_os:
  - Windows
  - macOS
  - Linux
cves:
  - id: CVE-2026-91732
    cvss: 8.1
    epss: 0.00261
    kev_status: "false"
references:
  - https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop.html
  - https://cyber.gc.ca/en/alerts-advisories/google-security-advisory-av26-1118
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-91732
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4417
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4518
  - https://cyber.gc.ca/en/alerts-advisories/google-security-advisory-av26-1157
  - https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_01744469280.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Google Chrome for Desktop to 157.0.8103.38 or higher
      owner: IT Operations
      addresses: Chrome for Desktop versions prior to 157.0.8103.38
      evidence: Source identifies versions prior to 157.0.8103.38/.39 as affected
    - priority: immediate
      action: Update Google Chrome to version 157.0.8103.78 (Linux) or 157.0.8103.78/.79 (Windows/Mac) or later.
      owner: IT Operations
      addresses: Chrome vulnerabilities mentioned in AV26-1157
      evidence: 'As of November 11, 2026, Google is affected by vulnerabilities in the following product: Stable Channel Chrome for Desktop'
updates:
  - at: "2026-11-05T10:38:32Z"
    level: L2
    summary: added CVE-2026-91732
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-91732
  - at: "2026-11-10T16:30:55Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4417
  - at: "2026-11-12T16:21:52Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4518
  - at: "2026-11-12T23:00:39Z"
    level: L1
    summary: added coverage for Chrome (< 157.0.8103.78)
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/google-security-advisory-av26-1157
---

Google has released security updates for the Stable Channel of Chrome for Desktop to address multiple vulnerabilities. The update addresses issues in versions prior to 157.0.8103.38/.39 (Windows/Mac) and 157.0.8103.38 (Linux). Google has not yet disclosed specific vulnerability details, including CVE identifiers, at the time of this report.

## Recommendation

- Update all instances of Google Chrome for Desktop to version 157.0.8103.38 or later for Linux, and 157.0.8103.38/.39 or later for Windows and macOS.
- Inventory systems running Google Chrome to ensure the browser auto-update mechanism is functioning correctly.
