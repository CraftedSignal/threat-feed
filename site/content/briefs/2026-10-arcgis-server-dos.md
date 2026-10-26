---
brief_id: brief-2026-10-26-arcgis-server-dos
event_id: brief-2026-10-26-arcgis-server-dos
revision: 1
activity_at: "2026-10-26T19:44:23Z"
title: 'Esri ArcGIS Server: Denial of Service (CVE-2026-33521)'
slug: 2026-10-arcgis-server-dos
description: Esri ArcGIS Server versions 12.0 and prior contain a denial of service vulnerability that may allow a remote, unauthenticated attacker to exhaust worker threads.
date: "2026-10-26T19:44:23Z"
type: advisory
types:
  - advisory
severities:
  - low
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
cves:
  - id: CVE-2026-33521
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33521
---

A denial of service vulnerability exists in Esri ArcGIS Server versions 12.0 and prior. A remote, unauthenticated attacker may supply crafted requests that, under exceptional circumstances, consume all available worker threads and deny service to users. 

Patches are provided for software in General Availability and Extended support status, including versions 11.1, 11.3, 11.5, and 12.0. Versions in mature or retired status are not patch eligible; users are advised to upgrade.
