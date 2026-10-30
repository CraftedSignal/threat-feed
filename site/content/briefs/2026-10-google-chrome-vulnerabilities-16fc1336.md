---
brief_id: brief-2026-10-28-google-chrome-vulnerabilities-16fc1336
event_id: brief-2026-10-28-google-chrome-vulnerabilities-16fc1336
revision: 3
activity_at: "2026-10-30T02:17:48Z"
revision_history:
  - revision: 2
    at: "2026-10-28T17:56:03Z"
    checksum: sha256:03c17a8b8e37f2ebc8d57c6f92d2e5fed4598f118e3936b7571c58fee000f688
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/chrome-156-security-update-oct-2026
  - revision: 3
    at: "2026-10-30T02:17:48Z"
    checksum: sha256:9cb4f83e6591e447308f97ec6011d9396fa1a09769737427e34e50669bb31996
    summary: OS android; OS windows; OS macos; OS linux
    changed_fields:
      - affected_os
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/chrome-156-security-update-oct-2026
title: 'Google Chrome: Multiple Vulnerabilities (CVE-2026-118304 through CVE-2026-118359)'
slug: 2026-10-google-chrome-vulnerabilities-16fc1336
description: Google has released security updates for Chrome addressing a large number of vulnerabilities affecting Linux, Windows, and macOS installations.
date: "2026-10-28T17:44:01Z"
lastmod: "2026-10-30T02:17:15Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - browser
  - vulnerability
  - patch-management
vendors:
  - Google
products:
  - Chrome (< 156.0.8078.73 for Linux)
  - Chrome (< 156.0.8078.73 for Windows)
  - Chrome (< 156.0.8078.74 for Mac)
  - Chrome (< 156.0.8078.73)
  - Chrome (< 156.0.8078.79)
affected_os:
  - Windows
  - macOS
  - Linux
  - Android
cves:
  - id: CVE-2026-118304
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118305
    kev_status: unknown
  - id: CVE-2026-118306
    cvss: 9.6
    epss: 0.00326
    kev_status: "false"
  - id: CVE-2026-118307
    cvss: 8.8
    epss: 0.00292
    kev_status: "false"
  - id: CVE-2026-118308
    kev_status: unknown
  - id: CVE-2026-118309
    kev_status: unknown
  - id: CVE-2026-118310
    cvss: 9.6
    epss: 0.00272
    kev_status: "false"
  - id: CVE-2026-118311
    cvss: 8.8
    epss: 0.00243
    kev_status: "false"
  - id: CVE-2026-118312
    kev_status: unknown
  - id: CVE-2026-118313
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118314
    kev_status: unknown
  - id: CVE-2026-118315
    cvss: 8.8
    epss: 0.00207
    kev_status: "false"
  - id: CVE-2026-118316
    kev_status: unknown
  - id: CVE-2026-118317
    kev_status: unknown
  - id: CVE-2026-118318
    kev_status: "false"
  - id: CVE-2026-118319
    kev_status: "false"
  - id: CVE-2026-118320
    kev_status: unknown
  - id: CVE-2026-118321
    kev_status: unknown
  - id: CVE-2026-118322
    kev_status: unknown
  - id: CVE-2026-118327
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118328
    kev_status: unknown
  - id: CVE-2026-118329
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118330
    kev_status: unknown
  - id: CVE-2026-118331
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118332
    cvss: 9.6
    epss: 0.00272
    kev_status: "false"
  - id: CVE-2026-118333
    kev_status: unknown
  - id: CVE-2026-118334
    cvss: 8.8
    epss: 0.00264
    kev_status: "false"
  - id: CVE-2026-118335
    kev_status: unknown
  - id: CVE-2026-118336
    kev_status: unknown
  - id: CVE-2026-118337
    kev_status: unknown
  - id: CVE-2026-118338
    kev_status: unknown
  - id: CVE-2026-118339
    cvss: 8.8
    epss: 0.00317
    kev_status: "false"
  - id: CVE-2026-118340
    kev_status: unknown
  - id: CVE-2026-118341
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118342
    kev_status: unknown
  - id: CVE-2026-118343
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118344
    kev_status: unknown
  - id: CVE-2026-118345
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118346
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118347
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118348
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118349
    kev_status: unknown
  - id: CVE-2026-118350
    kev_status: unknown
  - id: CVE-2026-118351
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118352
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118353
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118354
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-118355
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-118356
    kev_status: unknown
  - id: CVE-2026-118357
    cvss: 8.8
    epss: 0.00283
    kev_status: "false"
  - id: CVE-2026-118358
    cvss: 8.8
    epss: 0.00358
    kev_status: "false"
  - id: CVE-2026-118359
    cvss: 8.8
    epss: 0.00283
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1398/
  - https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html
  - https://www.cve.org/CVERecord?id=CVE-2026-118304
  - https://www.cve.org/CVERecord?id=CVE-2026-118305
  - https://www.cve.org/CVERecord?id=CVE-2026-118306
  - https://www.cve.org/CVERecord?id=CVE-2026-118307
  - https://www.cve.org/CVERecord?id=CVE-2026-118308
  - https://www.cve.org/CVERecord?id=CVE-2026-118309
  - https://www.cve.org/CVERecord?id=CVE-2026-118310
  - https://www.cve.org/CVERecord?id=CVE-2026-118311
  - https://www.cve.org/CVERecord?id=CVE-2026-118312
  - https://www.cve.org/CVERecord?id=CVE-2026-118313
  - https://www.cve.org/CVERecord?id=CVE-2026-118314
  - https://www.cve.org/CVERecord?id=CVE-2026-118315
  - https://www.cve.org/CVERecord?id=CVE-2026-118316
  - https://www.cve.org/CVERecord?id=CVE-2026-118317
  - https://www.cve.org/CVERecord?id=CVE-2026-118318
  - https://www.cve.org/CVERecord?id=CVE-2026-118319
  - https://www.cve.org/CVERecord?id=CVE-2026-118320
  - https://www.cve.org/CVERecord?id=CVE-2026-118321
  - https://www.cve.org/CVERecord?id=CVE-2026-118322
  - https://www.cve.org/CVERecord?id=CVE-2026-118327
  - https://www.cve.org/CVERecord?id=CVE-2026-118328
  - https://www.cve.org/CVERecord?id=CVE-2026-118329
  - https://www.cve.org/CVERecord?id=CVE-2026-118330
  - https://www.cve.org/CVERecord?id=CVE-2026-118331
  - https://www.cve.org/CVERecord?id=CVE-2026-118332
  - https://www.cve.org/CVERecord?id=CVE-2026-118333
  - https://www.cve.org/CVERecord?id=CVE-2026-118334
  - https://www.cve.org/CVERecord?id=CVE-2026-118335
  - https://www.cve.org/CVERecord?id=CVE-2026-118336
  - https://www.cve.org/CVERecord?id=CVE-2026-118337
  - https://www.cve.org/CVERecord?id=CVE-2026-118338
  - https://www.cve.org/CVERecord?id=CVE-2026-118339
  - https://www.cve.org/CVERecord?id=CVE-2026-118340
  - https://www.cve.org/CVERecord?id=CVE-2026-118341
  - https://www.cve.org/CVERecord?id=CVE-2026-118342
  - https://www.cve.org/CVERecord?id=CVE-2026-118343
  - https://www.cve.org/CVERecord?id=CVE-2026-118344
  - https://www.cve.org/CVERecord?id=CVE-2026-118345
  - https://www.cve.org/CVERecord?id=CVE-2026-118346
  - https://www.cve.org/CVERecord?id=CVE-2026-118347
  - https://www.cve.org/CVERecord?id=CVE-2026-118348
  - https://www.cve.org/CVERecord?id=CVE-2026-118349
  - https://www.cve.org/CVERecord?id=CVE-2026-118350
  - https://www.cve.org/CVERecord?id=CVE-2026-118351
  - https://www.cve.org/CVERecord?id=CVE-2026-118352
  - https://www.cve.org/CVERecord?id=CVE-2026-118353
  - https://www.cve.org/CVERecord?id=CVE-2026-118354
  - https://www.cve.org/CVERecord?id=CVE-2026-118355
  - https://www.cve.org/CVERecord?id=CVE-2026-118356
  - https://www.cve.org/CVERecord?id=CVE-2026-118357
  - https://www.cve.org/CVERecord?id=CVE-2026-118358
  - https://www.cve.org/CVERecord?id=CVE-2026-118359
  - https://pwn.watch/i/chrome-156-security-update-oct-2026
  - https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02018666648.html
  - https://www.anthropic.com/research/discovering-vulnerabilities-with-claude
  - https://cyber.gc.ca/en/alerts-advisories/google-chrome-security-advisory-av26-1095
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4210
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-122
  - https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02107719452.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Chrome instances to version 156.0.8078.73/74
      owner: IT Operations
      due: 48h
      evidence: Source notes vulnerabilities require stable channel update
  mitigation_plan:
    - priority: immediate
      action: Deploy patch to all endpoints
      owner: IT Operations
      addresses: All CVEs listed
      evidence: Chrome security bulletin dated October 27, 2026
updates:
  - at: "2026-10-28T17:55:18Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/chrome-156-security-update-oct-2026
  - at: "2026-10-30T02:17:15Z"
    level: L1
    summary: OS android; OS windows; OS macos; OS linux
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/chrome-156-security-update-oct-2026
---

Google has addressed multiple security vulnerabilities in the Chrome browser through a stable channel update released on October 27, 2026. The vulnerabilities cover a wide range of identified CVEs, though Google has not publicly specified the exact nature or exploitability of each flaw. Users are advised to update their browsers immediately to the latest stable versions to prevent exploitation.

## Recommendation

- Update Google Chrome to version 156.0.8078.73 or later on Linux and Windows.
- Update Google Chrome to version 156.0.8078.74 or later on macOS.
- Inventory browser versions across the enterprise to identify and patch outdated installations.
