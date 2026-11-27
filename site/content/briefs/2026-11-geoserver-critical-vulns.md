---
brief_id: brief-2026-11-25-geoserver-critical-vulns
event_id: brief-2026-11-25-geoserver-critical-vulns
revision: 3
activity_at: "2026-11-27T21:12:10Z"
revision_history:
  - revision: 2
    at: "2026-11-26T12:53:17Z"
    checksum: sha256:5558724af93cd2f3e1a3eca32e0ef292bc826f3293b5a9f390e1edeac0afce80
    summary: new vendor
    changed_fields:
      - affected_vendors
      - cve_verification
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.securityweek.com/two-newly-disclosed-geoserver-vulnerabilities-under-attack/
  - revision: 3
    at: "2026-11-27T21:12:10Z"
    checksum: sha256:a65de230ce0b967b2ade828c3ce4ecc8046228f469cdc45984c52face47bd527
    summary: KEV CVE-2026-120705; KEV CVE-2026-129243
    changed_fields:
      - cves
      - lastmod
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: GeoServer Security Advisory (AV26-1207)
slug: 2026-11-geoserver-critical-vulns
description: GeoServer versions prior to 2.27.7, 2.28.6, and 3.0.2 are affected by vulnerabilities (CVE-2026-120705 and CVE-2026-129243) currently being exploited in the wild.
date: "2026-11-25T23:21:19Z"
lastmod: "2026-11-27T21:11:35Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://cyber.gc.ca/en/alerts-advisories/geoserver-security-advisory-av26-1207
  observed_at: "2026-11-25T23:21:19Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
vendors:
  - GeoServer
products:
  - GeoServer
cve_verification:
  CVE-2026-120705:
    status: not_found
    source: cve_program
    checked_at: 2026-11-26T12:52:32.11778464Z
  CVE-2026-129243:
    status: not_found
    source: cve_program
    checked_at: 2026-11-26T12:52:32.365553535Z
cves:
  - id: CVE-2026-120705
    kev: true
    kev_status: "true"
  - id: CVE-2026-129243
    kev: true
    kev_status: "true"
references:
  - https://cyber.gc.ca/en/alerts-advisories/geoserver-security-advisory-av26-1207
  - https://geoserver.org/vulnerability/2026/11/23/cve-update.html
  - https://www.securityweek.com/two-newly-disclosed-geoserver-vulnerabilities-under-attack/
updates:
  - at: "2026-11-26T12:52:32Z"
    level: L1
    summary: new vendor
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/two-newly-disclosed-geoserver-vulnerabilities-under-attack/
  - at: "2026-11-27T21:11:35Z"
    level: L3
    summary: KEV CVE-2026-120705; KEV CVE-2026-129243
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview
On November 25, 2026, the Cyber Centre issued an advisory regarding vulnerabilities in GeoServer. Open source reporting indicates that CVE-2026-120705 and CVE-2026-129243 are being exploited in the wild.

## Attack Chain
The provided source does not specify the mechanisms of exploitation, attack stages, or impact.

## Impact
The provided source confirms active exploitation in the wild, but does not explicitly define the security impact.

## Recommendation
Administrators should review the vendor documentation at https://geoserver.org/vulnerability/2026/11/23/cve-update.html and apply updates for affected GeoServer versions prior to 2.27.7, 2.28.6, and 3.0.2.
