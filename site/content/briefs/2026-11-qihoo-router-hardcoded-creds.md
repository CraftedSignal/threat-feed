---
brief_id: brief-2026-11-04-qihoo-router-hardcoded-creds
event_id: brief-2026-11-04-qihoo-router-hardcoded-creds
revision: 1
activity_at: "2026-11-04T02:26:50Z"
title: Qihoo 360 Whole Home Router M5 hard-coded credentials (CVE-2026-121609)
slug: 2026-11-qihoo-router-hardcoded-creds
description: A vulnerability in Qihoo 360 Whole Home Router M5 4.0.17.1566 involves hard-coded credentials in the Home function of the /etc/init.d/mpt boot script.
date: "2026-11-04T02:26:50Z"
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
  - cpe:2.3:a:qihoo_360:whole_home_router_m5_4_0_17_1566:*:*:*:*:*:*:*:*
vendors:
  - Qihoo 360
products:
  - Whole Home Router M5 4.0.17.1566
cves:
  - id: CVE-2026-121609
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121609
---

A vulnerability was identified in the Home function of the /etc/init.d/mpt file within the Boot Script component of the Qihoo 360 Whole Home Router M5 4.0.17.1566. This manipulation leads to hard-coded credentials. The vulnerability allows for remote exploitation, and a public exploit is available. The vendor did not respond to disclosure attempts.
