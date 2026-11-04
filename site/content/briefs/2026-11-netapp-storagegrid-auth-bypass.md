---
brief_id: brief-2026-11-04-netapp-storagegrid-auth-bypass
event_id: brief-2026-11-04-netapp-storagegrid-auth-bypass
revision: 1
activity_at: "2026-11-04T00:46:14Z"
title: 'NetApp StorageGRID: Authentication bypass (CVE-2026-22058)'
slug: 2026-11-netapp-storagegrid-auth-bypass
description: NetApp StorageGRID versions 11.3 and higher are vulnerable to an authentication bypass (CVE-2026-22058) that allows unauthorized requests via the Grid Network. Public proof-of-concept exploit code has been published.
date: "2026-11-04T00:46:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:netapp:storagegrid:*:*:*:*:*:*:*:*
vendors:
  - NetApp
products:
  - StorageGRID (>= 11.3)
cves:
  - id: CVE-2026-22058
    kev_status: "false"
references:
  - https://security.netapp.com/advisory/NTAP-20261103-0001
  - https://sploitus.com/exploit?id=CVE-2026-22058
  - https://sploitus.com/exploit?id=CVE-2026-22058&utm_source=rss&utm_medium=rss
---

NetApp has disclosed a high severity authentication bypass vulnerability, tracked as CVE-2026-22058, affecting StorageGRID versions 11.3 and higher. An attacker with product-specific knowledge and the ability to communicate with the Grid Network can perform unauthorized requests. Public proof-of-concept exploit code is available on Sploitus.
