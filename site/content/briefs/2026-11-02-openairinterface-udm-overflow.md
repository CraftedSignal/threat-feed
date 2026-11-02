---
brief_id: brief-2026-11-02-openairinterface-udm-overflow
event_id: brief-2026-11-02-openairinterface-udm-overflow
revision: 1
activity_at: "2026-11-02T19:49:26Z"
title: 'OpenAirInterface Core Network: Stack-based buffer overflow in UDM (CVE-2026-106808)'
slug: 2026-11-02-openairinterface-udm-overflow
description: OpenAirInterface Core Network v2.2.1 contains a stack-based buffer overflow in the Nudm_UEAU Generate Authentication Data endpoint, allowing an unauthenticated attacker to terminate the UDM process.
date: "2026-11-02T19:49:26Z"
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
  - cpe:2.3:a:openairinterface:core_network:2.2.1:*:*:*:*:*:*:*
vendors:
  - OpenAirInterface
products:
  - OpenAirInterface Core Network (v2.2.1)
cves:
  - id: CVE-2026-106808
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106808
---

A stack-based buffer overflow vulnerability exists in OpenAirInterface (OAI) Core Network v2.2.1 within the Nudm_UEAU Generate Authentication Data endpoint. The UDM fails to validate the size of `resynchronizationInfo.rand` and `auts` values when passed to `conv::hex_str_to_uint8()`. An unauthenticated attacker with access to the SBI interface and a valid SUPI can provide an oversized value to overwrite adjacent stack memory and the stack canary, causing the UDM process to terminate.
