---
brief_id: brief-2026-10-27-libiec61850-goose-replay
event_id: brief-2026-10-27-libiec61850-goose-replay
revision: 1
activity_at: "2026-10-27T01:09:36Z"
title: 'MZ Automation libiec61850: GOOSE message replay state rollback (CVE-2026-52134)'
slug: 2026-10-libiec61850-goose-replay
description: The libiec61850 library v1.6 fails to sufficiently reject replayed or outdated GOOSE messages, which can cause subscribers to update state or trigger callbacks with stale data.
date: "2026-10-27T01:09:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:mz_automation:libiec61850:*:*:*:*:*:*:*:*
vendors:
  - MZ Automation GmbH
products:
  - libiec61850 (1.6)
cves:
  - id: CVE-2026-52134
    cvss: 9.8
    epss: 0.008
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IF-FORGET-CVE-2026-52134-LIBIEC61850
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IF-FORGET-CVE-2026-52134-LIBIEC61850&utm_source=rss&utm_medium=rss
---

CVE-2026-52134 affects the `parseGoosePayload()` function in `src/goose/goose_receiver.c` of libiec61850 v1.6. Controlled experiments demonstrated that replaying captured GOOSE frames can trigger state rollbacks (where a subscriber reverts to a lower `stNum`) or cause the library to trigger listener callbacks for messages marked as invalid. 

## Prerequisites
To conduct the described replay behavior, an actor must be able to access the relevant IEEE 802.3 Layer 2 broadcast domain or VLAN, capture legitimate GOOSE Ethernet frames (EtherType 0x88B8), and inject frames into the network.
