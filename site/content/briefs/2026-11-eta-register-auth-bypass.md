---
brief_id: brief-2026-11-03-eta-register-auth-bypass
event_id: brief-2026-11-03-eta-register-auth-bypass
revision: 1
activity_at: "2026-11-03T03:50:31Z"
title: 'TÜBİTAK BİLGEM eta-register: Missing authorization privilege escalation (CVE-2026-92886)'
slug: 2026-11-eta-register-auth-bypass
description: A missing authorization vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute eta-register allows Privilege Escalation.
date: "2026-11-03T03:50:31Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:t_bitak_bilgem_software_technologies_research_institute:eta_register:*:*:*:*:*:*:*:*
vendors:
  - TÜBİTAK BİLGEM Software Technologies Research Institute
products:
  - eta-register (< 2.0.9)
cves:
  - id: CVE-2026-92886
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92886
---

CVE-2026-92886 identifies a Missing Authorization vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute eta-register. This vulnerability allows Privilege Escalation. This issue affects eta-register: from 2.0.8 before 2.0.9.
