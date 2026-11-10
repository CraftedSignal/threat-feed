---
brief_id: brief-2026-11-10-eta-remote-acl
event_id: brief-2026-11-10-eta-remote-acl
revision: 1
activity_at: "2026-11-10T14:33:48Z"
title: 'TÜBİTAK BİLGEM eta-remote: Incorrect default permissions (CVE-2026-121267)'
slug: 2026-11-eta-remote-acl
description: An incorrect default permissions vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute eta-remote allows accessing functionality not properly constrained by ACLs.
date: "2026-11-10T14:33:48Z"
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
  - cpe:2.3:a:t_bitak_bilgem_software_technologies_research_institute:eta_remote:*:*:*:*:*:*:*:*
vendors:
  - TÜBİTAK BİLGEM Software Technologies Research Institute
products:
  - eta-remote (< 0.0.3)
cves:
  - id: CVE-2026-121267
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121267
---

CVE-2026-121267 describes an incorrect default permissions vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute eta-remote (versions 0.0.2 before 0.0.3). The vulnerability allows for accessing functionality that is not properly constrained by Access Control Lists (ACLs). The CVSS v3.1 base score is 7.8.
