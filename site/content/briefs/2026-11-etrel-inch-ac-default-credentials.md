---
brief_id: brief-2026-11-04-etrel-inch-ac-default-credentials
event_id: brief-2026-11-04-etrel-inch-ac-default-credentials
revision: 1
activity_at: "2026-11-04T00:23:51Z"
title: 'Etrel INCH AC: Management web interface default credentials (CVE-2026-112354)'
slug: 2026-11-etrel-inch-ac-default-credentials
description: Etrel INCH AC charging station management web interface contains a hard-coded default credentials vulnerability.
date: "2026-11-04T00:23:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:etrel:inch_ac:*:*:*:*:*:*:*:*
vendors:
  - Etrel
products:
  - INCH AC
cves:
  - id: CVE-2026-112354
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112354
---

Etrel INCH AC charging station management web interface prior to firmware versions 7.1.2 and 8.0.1 contains a hard-coded default credentials vulnerability that allows remote attackers to gain full Administrator access by authenticating with the factory-default account. Attackers can log in over cleartext HTTP to obtain complete charger configuration, OCPP ChargePoint Identity, and CSMS WebSocket connection details, enabling unauthorized administrative control of the charging station.
