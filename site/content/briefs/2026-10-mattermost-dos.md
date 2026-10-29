---
brief_id: brief-2026-10-29-mattermost-dos
event_id: brief-2026-10-29-mattermost-dos
revision: 1
activity_at: "2026-10-29T19:54:44Z"
title: 'Mattermost Server: Remote Denial of Service'
slug: 2026-10-mattermost-dos
description: A vulnerability has been discovered in Mattermost Server that allows a remote attacker to cause a denial of service.
date: "2026-10-29T19:54:44Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - Mattermost Server versions 11.7.x before 11.7.11
  - Mattermost Server versions 11.8.x before 11.8.6
  - Mattermost Server versions 11.9.x before 11.9.2
  - Mattermost Server versions before 11.10.0
cves:
  - id: CVE-2026-116516
    cvss: 6.5
    epss: 0.00362
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1388/
  - https://mattermost.com/security-updates/
  - https://www.cve.org/CVERecord?id=CVE-2026-116516
---

A vulnerability exists in Mattermost Server which allows an attacker to perform a remote denial of service. The vulnerability is detailed in Mattermost security bulletin MMSA-2026-00723. Users are advised to refer to the vendor's security bulletin for patch information.
