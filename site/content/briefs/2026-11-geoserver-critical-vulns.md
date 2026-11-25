---
brief_id: brief-2026-11-25-geoserver-critical-vulns
event_id: brief-2026-11-25-geoserver-critical-vulns
revision: 1
activity_at: "2026-11-25T23:21:19Z"
title: GeoServer Security Advisory (AV26-1207)
slug: 2026-11-geoserver-critical-vulns
description: GeoServer versions prior to 2.27.7, 2.28.6, and 3.0.2 are affected by vulnerabilities (CVE-2026-120705 and CVE-2026-129243) currently being exploited in the wild.
date: "2026-11-25T23:21:19Z"
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
products:
  - GeoServer
cves:
  - id: CVE-2026-120705
    kev_status: "false"
  - id: CVE-2026-129243
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/geoserver-security-advisory-av26-1207
  - https://geoserver.org/vulnerability/2026/11/23/cve-update.html
---

## Overview
On November 25, 2026, the Cyber Centre issued an advisory regarding vulnerabilities in GeoServer. Open source reporting indicates that CVE-2026-120705 and CVE-2026-129243 are being exploited in the wild.

## Attack Chain
The provided source does not specify the mechanisms of exploitation, attack stages, or impact.

## Impact
The provided source confirms active exploitation in the wild, but does not explicitly define the security impact.

## Recommendation
Administrators should review the vendor documentation at https://geoserver.org/vulnerability/2026/11/23/cve-update.html and apply updates for affected GeoServer versions prior to 2.27.7, 2.28.6, and 3.0.2.
