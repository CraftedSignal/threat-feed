---
brief_id: brief-2026-11-01-wavlink-wn701ae-rce
event_id: brief-2026-11-01-wavlink-wn701ae-rce
revision: 1
activity_at: "2026-11-01T16:56:55Z"
title: 'Wavlink WN701AE: Remote OS Command Injection in ioos Web Backend (CVE-2026-120230)'
slug: 2026-11-wavlink-wn701ae-rce
description: A vulnerability in the Wavlink WN701AE (260105) ioos Web Backend allows remote OS command injection via the vlan_name argument in the del_vlan_group function.
date: "2026-11-01T16:56:55Z"
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
products:
  - Wavlink WN701AE 260105
cves:
  - id: CVE-2026-120230
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120230
---

A vulnerability exists in the ioos Web Backend of Wavlink WN701AE 260105. The `del_vlan_group` function is susceptible to OS command injection through the `vlan_name` argument. This attack can be performed remotely, and public exploit code is available. The vendor was notified of this disclosure.
