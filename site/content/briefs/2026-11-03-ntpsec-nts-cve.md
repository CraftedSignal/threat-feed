---
brief_id: brief-2026-11-03-ntpsec-nts-cve
event_id: brief-2026-11-03-ntpsec-nts-cve
revision: 1
activity_at: "2026-11-03T16:01:24Z"
title: 'NTPsec: Heap memory corruption via NTS client extension field parsing (CVE-2026-121506)'
slug: 2026-11-03-ntpsec-nts-cve
description: NTPsec before 1.2.5 is vulnerable to an out-of-bounds read and write in NTS client extension field parsing, which can lead to heap memory corruption, service crashes, and authentication bypass.
date: "2026-11-03T16:01:24Z"
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
cpes:
  - cpe:2.3:a:ntpsec:ntpsec:*:*:*:*:*:*:*:*
vendors:
  - NTPsec
products:
  - NTPsec (< 1.2.5)
cves:
  - id: CVE-2026-121506
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121506
---

An out-of-bounds read and write in NTS client extension field parsing (extens_client_recv) in NTPsec before 1.2.5 allows a remote attacker who can send NTP server-mode replies to an NTS client to corrupt heap memory and crash ntpd. When combined with an NTS-KE client out-of-bounds read vulnerability (fixed in 1.2.4), an attacker can bypass NTS authentication and set the client's time via an NTS Authenticator and Encrypted Extension Fields field whose nonce length exceeds the field.
