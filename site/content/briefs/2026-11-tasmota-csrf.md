---
brief_id: brief-2026-11-09-tasmota-csrf
event_id: brief-2026-11-09-tasmota-csrf
revision: 1
activity_at: "2026-11-09T19:51:03Z"
title: 'Tasmota: Cross-site request forgery via Referer header bypass (CVE-2026-119755)'
slug: 2026-11-tasmota-csrf
description: Tasmota through 16.0.0 contains a cross-site request forgery vulnerability in HttpCheckPriviledgedAccess() allowing Referer-based protection bypass.
date: "2026-11-09T19:51:03Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Tasmota (<= 16.0.0)
cves:
  - id: CVE-2026-119755
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119755
---

Tasmota through 16.0.0, fixed in commit 1cb7ebc, contains a cross-site request forgery vulnerability that allows unauthenticated attackers to bypass Referer-based CSRF protection in HttpCheckPriviledgedAccess() by crafting a Referer header where the device hostname or IP appears as a substring immediately after http://.evil.com/. Attackers can lure an administrator on the device's network to a malicious page to issue arbitrary console commands and reconfigure Wi-Fi, MQTT, settings, or firmware on devices lacking a WebPassword. The CVSS v3.1 base score is 7.5.
