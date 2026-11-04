---
brief_id: brief-2026-11-04-netapp-storagegrid-auth-bypass
event_id: brief-2026-11-04-netapp-storagegrid-auth-bypass
revision: 2
activity_at: "2026-11-04T16:18:46Z"
revision_history:
  - revision: 2
    at: "2026-11-04T16:18:46Z"
    checksum: sha256:40548f619408b05eae8d6ee76f4ee86c4c824c2fe89732ec295213db65c670ab
    summary: added coverage for StorageGRID
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - qa_status
      - references
      - tags
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4318
title: 'NetApp StorageGRID: Authentication bypass (CVE-2026-22058)'
slug: 2026-11-netapp-storagegrid-auth-bypass
description: NetApp StorageGRID versions 11.3 and higher are vulnerable to an authentication bypass (CVE-2026-22058) that allows unauthorized requests via the Grid Network. Public proof-of-concept exploit code has been published.
date: "2026-11-04T00:46:14Z"
lastmod: "2026-11-04T16:18:11Z"
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:netapp:storagegrid:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - netapp
  - storagegrid
vendors:
  - NetApp
products:
  - StorageGRID (>= 11.3)
  - StorageGRID
cves:
  - id: CVE-2026-22058
    kev_status: "false"
references:
  - https://security.netapp.com/advisory/NTAP-20261103-0001
  - https://sploitus.com/exploit?id=CVE-2026-22058
  - https://sploitus.com/exploit?id=CVE-2026-22058&utm_source=rss&utm_medium=rss
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4318
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - CTI
  immediate_actions:
    - action: Inventory all NetApp StorageGRID instances.
      owner: IT Operations
      due: 24h
      evidence: BSI security advisory indicates multiple vulnerabilities in the product
  enrichment_needed:
    - item: Affected version ranges
      owner: CTI
      reason: Necessary to determine patch requirements
      evidence: Advisory does not specify version numbers
  mitigation_plan:
    - priority: immediate
      action: Monitor NetApp security bulletin and apply patches as soon as they become available.
      owner: IT Operations
      addresses: NetApp StorageGRID
      evidence: BSI WID-SEC-2026-4318
updates:
  - at: "2026-11-04T16:18:11Z"
    level: L1
    summary: added coverage for StorageGRID
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4318
---

NetApp has disclosed a high severity authentication bypass vulnerability, tracked as CVE-2026-22058, affecting StorageGRID versions 11.3 and higher. An attacker with product-specific knowledge and the ability to communicate with the Grid Network can perform unauthorized requests. Public proof-of-concept exploit code is available on Sploitus.
