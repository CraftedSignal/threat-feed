---
brief_id: brief-2026-10-28-juniper-session-smart-conductor
event_id: brief-2026-10-28-juniper-session-smart-conductor
revision: 2
activity_at: "2026-10-28T19:24:42Z"
revision_history:
  - revision: 2
    at: "2026-10-28T19:24:42Z"
    checksum: sha256:b5be23b00036b1b082753c49032cb59e71bd90da7c2c6900d35afc5730e78392
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-103406&utm_source=rss&utm_medium=rss
title: 'Juniper Networks Session Smart Conductor: Improper OS Command Neutralization (CVE-2026-103406)'
slug: 2026-10-juniper-session-smart-conductor
description: An Improper Neutralization of Special Elements used in an OS Command vulnerability in the AutomatedProvisioner in Juniper Networks Session Smart Conductor allows a remote attacker to execute arbitrary commands as root via a specially crafted salt minion ID.
date: "2026-10-28T18:36:48Z"
lastmod: "2026-10-28T19:23:53Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:juniper_networks:session_smart_conductor:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-103406&utm_source=rss&utm_medium=rss
vendors:
  - Juniper Networks
products:
  - Session Smart Conductor
cves:
  - id: CVE-2026-103406
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103406
  - https://sploitus.com/exploit?id=CVE-2026-103406&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-28T19:23:53Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-103406&utm_source=rss&utm_medium=rss
---

CVE-2026-103406 identifies a vulnerability in the AutomatedProvisioner component of Juniper Networks Session Smart Conductor. A remote attacker can execute arbitrary commands as root by utilizing a specially crafted salt minion ID.
