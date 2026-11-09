---
brief_id: brief-2026-11-09-tasmota-oob-write
event_id: brief-2026-11-09-tasmota-oob-write
revision: 1
activity_at: "2026-11-09T19:50:51Z"
title: 'Tasmota: Heap out-of-bounds write in SendReceiveDeviceGroupMessage (CVE-2026-119756)'
slug: 2026-11-tasmota-oob-write
description: Tasmota versions through 16.0.0 contain a heap out-of-bounds write vulnerability in the SendReceiveDeviceGroupMessage() function that allows unauthenticated local network attackers to trigger memory corruption via crafted UDP packets.
date: "2026-11-09T19:50:51Z"
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
  - cpe:2.3:a:tasmota:tasmota:*:*:*:*:*:*:*:*
vendors:
  - Tasmota
products:
  - Tasmota (<= 16.0.0)
cves:
  - id: CVE-2026-119756
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119756
---

Tasmota through 16.0.0, fixed in commit e97e1e4, contains a heap out-of-bounds write vulnerability in SendReceiveDeviceGroupMessage() that allows unauthenticated attackers on the local network to corrupt heap memory by sending crafted Device Groups messages over UDP port 4447. This causes the log_remaining counter to go negative and writes to exceed the fixed 512-byte buffer. Attackers can exploit this flaw to crash the device or potentially achieve native code execution on ESP8266 and ESP32 platforms.
