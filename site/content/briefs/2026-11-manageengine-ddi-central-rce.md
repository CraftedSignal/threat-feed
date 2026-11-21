---
brief_id: brief-2026-11-10-manageengine-ddi-central-rce
event_id: brief-2026-11-10-manageengine-ddi-central-rce
revision: 2
activity_at: "2026-11-21T22:46:57Z"
revision_history:
  - revision: 2
    at: "2026-11-21T22:46:57Z"
    checksum: sha256:c48034098cfb3566837d77f26d2bfb845918ddbd8ca8338398f1846f102869b4
    summary: 'exploitation evidence corrected: an exploit-code listing is not exploitation'
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_signals
      - updates
title: 'ManageEngine DDI Central: Authenticated command injection (CVE-2026-12573)'
slug: 2026-11-manageengine-ddi-central-rce
description: ManageEngine DDI Central is affected by an authenticated command injection vulnerability (CVE-2026-12573) that allows for arbitrary command execution on managed Cisco routers via the DHCP pool name.
date: "2026-11-10T17:00:10Z"
lastmod: "2026-11-21T22:46:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
cpes:
  - cpe:2.3:a:zoho:manageengine_ddi_central:*:*:*:*:*:*:*:*
vendors:
  - Zoho Corporation
products:
  - ManageEngine DDI Central
cves:
  - id: CVE-2026-12573
    cvss: 8.8
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=CVE-2026-12573
  - https://www.manageengine.com/dns-dhcp-ipam/security-updates/security-updates.html
  - https://sploitus.com/exploit?id=CVE-2026-12573&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-21T22:46:14Z"
    level: L1
    summary: 'exploitation evidence corrected: an exploit-code listing is not exploitation'
    sources:
      - threat-bot
---

A public proof-of-concept exploit is available for CVE-2026-12573. The vulnerability allows an authenticated attacker to inject arbitrary commands into Cisco routers managed by ManageEngine DDI Central by manipulating the DHCP pool name field.
