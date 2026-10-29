---
brief_id: brief-2026-10-29-yamaha-nwr100-rce
event_id: brief-2026-10-29-yamaha-nwr100-rce
revision: 1
activity_at: "2026-10-29T13:23:30Z"
title: 'Yamaha NWR100: OS command injection (CVE-2026-97854)'
slug: 2026-10-yamaha-nwr100-rce
description: The Yamaha NWR100 wireless LAN router is susceptible to an OS command injection vulnerability, allowing arbitrary OS commands to be executed via a specially crafted request.
date: "2026-10-29T13:23:30Z"
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
  - cpe:2.3:h:yamaha:nwr100:*:*:*:*:*:*:*:*
vendors:
  - Yamaha
products:
  - NWR100
cves:
  - id: CVE-2026-97854
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97854
---

The Yamaha wireless LAN router NWR100 contains an OS command injection vulnerability (CVE-2026-97854). Arbitrary OS commands may be executed by sending a specially crafted request to the affected product.
