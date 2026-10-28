---
brief_id: brief-2026-10-28-juniper-session-smart-conductor
event_id: brief-2026-10-28-juniper-session-smart-conductor
revision: 1
activity_at: "2026-10-28T18:36:48Z"
title: 'Juniper Networks Session Smart Conductor: Improper OS Command Neutralization (CVE-2026-103406)'
slug: 2026-10-juniper-session-smart-conductor
description: An Improper Neutralization of Special Elements used in an OS Command vulnerability in the AutomatedProvisioner in Juniper Networks Session Smart Conductor allows a remote attacker to execute arbitrary commands as root via a specially crafted salt minion ID.
date: "2026-10-28T18:36:48Z"
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
  - cpe:2.3:a:juniper_networks:session_smart_conductor:*:*:*:*:*:*:*:*
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
---

CVE-2026-103406 identifies a vulnerability in the AutomatedProvisioner component of Juniper Networks Session Smart Conductor. A remote attacker can execute arbitrary commands as root by utilizing a specially crafted salt minion ID.
