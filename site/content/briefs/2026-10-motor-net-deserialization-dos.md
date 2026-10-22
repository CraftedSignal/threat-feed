---
brief_id: brief-2026-10-22-motor-net-deserialization-dos
event_id: brief-2026-10-22-motor-net-deserialization-dos
revision: 1
activity_at: "2026-10-22T22:30:58Z"
title: 'Motor.NET: Denial of service via JsonNetDeserializer exception handling (CVE-2026-112332)'
slug: 2026-10-motor-net-deserialization-dos
description: Motor.NET versions before 0.19.0 contain an uncaught exception vulnerability in JsonNetDeserializer.Deserialize that can cause a permanent crash-loop.
date: "2026-10-22T22:30:58Z"
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
  - Motor.NET (< 0.19.0)
cves:
  - id: CVE-2026-112332
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112332
---

Motor.NET before 0.19.0 contains an uncaught exception vulnerability in JsonNetDeserializer.Deserialize. A remote attacker who can publish to a consumed queue or topic can crash the service permanently by sending structurally valid JSON that does not match the handler's expected type. The failure to catch JsonSerializationException causes TypedConsumerService.SingleMessageConsumeAsync to call StopApplication; the resulting redelivery of the unacknowledged message on restart leads to a permanent crash-loop.
