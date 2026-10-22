---
brief_id: brief-2026-10-22-motor-net-dos
event_id: brief-2026-10-22-motor-net-dos
revision: 1
activity_at: "2026-10-22T22:30:50Z"
title: 'Motor.NET: Denial of Service via crafted cloudEvents headers (CVE-2026-112330)'
slug: 2026-10-motor-net-dos
description: Motor.NET versions before 0.19.0 contain a denial of service vulnerability where crafted cloudEvents headers trigger a fatal exception in ExtractCloudEvent, causing a permanent crash-loop upon message redelivery.
date: "2026-10-22T22:30:50Z"
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
products:
  - Motor.NET before 0.19.0 (< 0.19.0)
cves:
  - id: CVE-2026-112330
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112330
---

Motor.NET before 0.19.0 contains a denial of service vulnerability. A remote attacker who can publish to a consumed queue can crash the service permanently by sending a message with crafted cloudEvents headers. Attackers can supply an invalid cloudEvents:motorversion, a single double-quote header value, or an unparsable typed attribute such as cloudEvents:time to trigger an unhandled exception in ExtractCloudEvent that is treated as fatal. This results in the application stopping and the unacknowledged message being redelivered on restart, causing a permanent crash-loop.
