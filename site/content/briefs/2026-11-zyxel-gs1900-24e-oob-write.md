---
brief_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
event_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
revision: 3
activity_at: "2026-11-03T21:28:45Z"
revision_history:
  - revision: 2
    at: "2026-11-03T04:05:53Z"
    checksum: sha256:91e4c05562b77df30716736c2209223a93a0a5b6d4e2abf4fefa70ea6d9723e9
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-11-03T21:28:45Z"
    checksum: sha256:283c7c423a0581b9469fd2a4c7bef8b8f017fa0b6b210b25adb7b8c89cf08d53
    summary: added coverage for GS1900 series switches +3 products
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority_signals
      - qa_status
      - references
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/zyxel-security-advisory-av26-1114
title: 'Zyxel GS1900-24E: Out-of-bounds write vulnerability (CVE-2026-107441)'
slug: 2026-11-zyxel-gs1900-24e-oob-write
description: An out-of-bounds write vulnerability in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0 could allow an unauthenticated adjacent attacker to potentially execute OS commands via a crafted HTTP request.
date: "2026-11-03T03:50:17Z"
lastmod: "2026-11-03T21:28:09Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Advisory details are sparse regarding specific CVE IDs; recommend following vendor advisory links for latest technical updates.
cpes:
  - cpe:2.3:a:zyxel:gs1900_24e:*:*:*:*:*:*:*:*
  - cpe:2.3:a:zyxel:nwa110ax:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
vendors:
  - Zyxel
products:
  - GS1900-24E (through firmware 2.90(AAHK.2)C0)
  - NWA110AX (<= 7.12)
  - GS1900 series switches
  - APs
  - FWA7
  - Security Routers
cves:
  - id: CVE-2026-107441
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-76955
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107441
  - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=CVE-2026-76955
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-buffer-overflow-vulnerability-in-certain-aps-fwa7-and-security-routers-11-03-2026
  - https://sploitus.com/exploit?id=CVE-2026-76955&utm_source=rss&utm_medium=rss
  - https://cyber.gc.ca/en/alerts-advisories/zyxel-security-advisory-av26-1114
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-out-of-bounds-write-vulnerability-in-gs1900-series-switches-11-03-2026
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Check Zyxel security portal for latest firmware updates for GS1900 series, APs, FWA7, and security routers
      owner: IT Operations
      addresses: Out-of-bounds write and buffer overflow vulnerabilities
      evidence: Zyxel security advisory AV26-1114
updates:
  - at: "2026-11-03T04:05:16Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
  - at: "2026-11-03T21:28:09Z"
    level: L2
    summary: added CVE-2026-76955
    sources:
      - sploitus
  - at: "2026-11-03T21:28:09Z"
    level: L1
    summary: added coverage for GS1900 series switches +3 products
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/zyxel-security-advisory-av26-1114
---

An out-of-bounds write vulnerability exists in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0. This flaw may allow an unauthenticated adjacent attacker to potentially execute OS commands via a crafted HTTP request. The vulnerability is identified as CVE-2026-107441 with a CVSS v3.1 base score of 8.8.
