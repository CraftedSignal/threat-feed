---
brief_id: brief-2026-11-03-zyxel-buffer-overflow
event_id: brief-2026-11-03-zyxel-buffer-overflow
revision: 1
activity_at: "2026-11-03T04:05:12Z"
title: 'Zyxel NWA110AX: Buffer overflow in zdp_wtp binary (CVE-2026-76955)'
slug: 2026-11-zyxel-buffer-overflow
description: A buffer overflow vulnerability in the zdp_wtp binary of Zyxel NWA110AX allows for LAN-based privilege escalation.
date: "2026-11-03T04:05:12Z"
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
  - cpe:2.3:a:zyxel:nwa110ax:*:*:*:*:*:*:*:*
vendors:
  - Zyxel
products:
  - NWA110AX (<= 7.12)
cves:
  - id: CVE-2026-76955
    cvss: 8.8
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=CVE-2026-76955
  - https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-buffer-overflow-vulnerability-in-certain-aps-fwa7-and-security-routers-11-03-2026
  - https://sploitus.com/exploit?id=CVE-2026-76955&utm_source=rss&utm_medium=rss
---

A buffer overflow vulnerability exists in the zdp_wtp binary of the Zyxel NWA110AX, which allows a LAN-based attacker to escalate privileges on the device. A public exploit or PoC has been published on Sploitus for this CVE.
