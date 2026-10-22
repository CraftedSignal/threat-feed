---
brief_id: brief-2026-10-22-openremote-auth-bypass
event_id: brief-2026-10-22-openremote-auth-bypass
revision: 1
activity_at: "2026-10-22T03:52:54Z"
title: 'OpenRemote: Missing authorization vulnerability in GatewayServiceResource (CVE-2026-114661)'
slug: 2026-10-openremote-auth-bypass
description: OpenRemote 1.2.0 before 1.31.0 contains a missing authorization vulnerability in GatewayServiceResource that allows any authenticated user to start, stop and query gateway tunnels without an administrative role.
date: "2026-10-22T03:52:54Z"
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
  - cpe:2.3:a:openremote:openremote:*:*:*:*:*:*:*:*
vendors:
  - OpenRemote
products:
  - OpenRemote (1.2.0 before 1.31.0)
cves:
  - id: CVE-2026-114661
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114661
---

OpenRemote 1.2.0 before 1.31.0 contains a missing authorization vulnerability in GatewayServiceResource that allows any authenticated user to start, stop, and query gateway tunnels without an administrative role. Attackers can send POST or DELETE requests to the gateway tunnel endpoint to open persistent bidirectional TCP circuits into an edge gateway's network or tear down operator tunnels.
