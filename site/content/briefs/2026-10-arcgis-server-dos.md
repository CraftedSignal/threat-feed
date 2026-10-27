---
brief_id: brief-2026-10-26-arcgis-server-dos
event_id: brief-2026-10-26-arcgis-server-dos
revision: 3
activity_at: "2026-10-27T05:14:06Z"
revision_history:
  - revision: 2
    at: "2026-10-26T23:48:33Z"
    checksum: sha256:af37125d8aefeefe41992e7aff1d5e4da0213c2a0efcabd8d561fc6646b505c3
    summary: severity → critical; added CVE-2026-10757
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-10757
  - revision: 3
    at: "2026-10-27T05:14:06Z"
    checksum: sha256:deb2d875b893aab37566f5784a96d998ef02f11d98126606a0901b7508e0768d
    summary: added CVE-2026-33520 +2
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/esri-arcgis-server-sqli-cve-2026-10757
title: 'Esri ArcGIS Server: Denial of Service (CVE-2026-33521)'
slug: 2026-10-arcgis-server-dos
description: Esri ArcGIS Server versions 12.0 and prior contain a denial of service vulnerability that may allow a remote, unauthenticated attacker to exhaust worker threads.
date: "2026-10-26T19:44:23Z"
lastmod: "2026-10-27T05:13:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:esri:arcgis_server:*:*:*:*:*:*:*:*
vendors:
  - Esri
products:
  - ArcGIS Server (<= 12.0)
  - ArcGIS Server (<= 12.1)
cves:
  - id: CVE-2026-33521
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-10757
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-33522
    cvss: 5.3
    kev_status: "false"
  - id: CVE-2026-33520
    cvss: 6.1
    kev_status: "false"
  - id: CVE-2026-50095
    cvss: 6.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33521
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10757
  - https://pwn.watch/i/esri-arcgis-server-sqli-cve-2026-10757
  - https://www.esri.com/arcgis-blog/products/trust-arcgis/administration/october-2026-arcgis-security-bulletin
updates:
  - at: "2026-10-26T23:47:50Z"
    level: L3
    summary: severity → critical; added CVE-2026-10757
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-10757
  - at: "2026-10-27T05:13:33Z"
    level: L2
    summary: added CVE-2026-33520 +2
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/esri-arcgis-server-sqli-cve-2026-10757
---

A denial of service vulnerability exists in Esri ArcGIS Server versions 12.0 and prior. A remote, unauthenticated attacker may supply crafted requests that, under exceptional circumstances, consume all available worker threads and deny service to users. 

Patches are provided for software in General Availability and Extended support status, including versions 11.1, 11.3, 11.5, and 12.0. Versions in mature or retired status are not patch eligible; users are advised to upgrade.
