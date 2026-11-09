---
brief_id: brief-2026-11-09-aapanel-billionmail-injection
event_id: brief-2026-11-09-aapanel-billionmail-injection
revision: 1
activity_at: "2026-11-09T09:37:25Z"
title: 'aaPanel BillionMail: Injection vulnerability in Relay Configuration API (CVE-2026-124579)'
slug: 2026-11-aapanel-billionmail-injection
description: An injection vulnerability exists in the Relay Configuration API of aaPanel BillionMail up to version 4.9.
date: "2026-11-09T09:37:25Z"
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
  - cpe:2.3:a:aapanel:billionmail:*:*:*:*:*:*:*:*
vendors:
  - aaPanel
products:
  - BillionMail (up to 4.9)
cves:
  - id: CVE-2026-124579
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124579
---

A vulnerability exists in aaPanel BillionMail up to 4.9 within the 'core/api/relay/v1/relay.go' file of the Relay Configuration API. Manipulating the 'helo_name' argument can lead to injection. The attack may be performed from remote. The exploit has been publicly disclosed. The vendor did not respond to disclosure attempts.
