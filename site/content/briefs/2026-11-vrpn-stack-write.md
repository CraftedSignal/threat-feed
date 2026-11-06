---
brief_id: brief-2026-11-06-vrpn-stack-write
event_id: brief-2026-11-06-vrpn-stack-write
revision: 1
activity_at: "2026-11-06T05:28:19Z"
title: 'VRPN: Out-of-bounds stack write (CVE-2026-123200)'
slug: 2026-11-vrpn-stack-write
description: VRPN through 07.36 contains an out-of-bounds stack write vulnerability that allows unauthenticated remote peers to crash the process.
date: "2026-11-06T05:28:19Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - VRPN (through 07.36)
cves:
  - id: CVE-2026-123200
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123200
---

VRPN through 07.36 contains an out-of-bounds stack write vulnerability in vrpn_Endpoint::handle_sender_message() and handle_type_message(). An unauthenticated remote peer can connect, complete the version-cookie exchange, and send a SENDER_DESCRIPTION or TYPE_DESCRIPTION message with an out-of-range or negative index to crash the process.
