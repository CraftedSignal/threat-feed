---
brief_id: brief-2026-11-09-c-prot-appdefense-privilege-escalation
event_id: brief-2026-11-09-c-prot-appdefense-privilege-escalation
revision: 1
activity_at: "2026-11-09T13:48:36Z"
title: 'C-Prot AppDefense: Improperly controlled modification of dynamically-determined object attributes (CVE-2026-95648)'
slug: 2026-11-c-prot-appdefense-privilege-escalation
description: C-Prot AppDefense contains an improperly controlled modification of dynamically-determined object attributes vulnerability that allows privilege escalation.
date: "2026-11-09T13:48:36Z"
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
  - cpe:2.3:a:c_prot:appdefense:*:*:*:*:*:*:*:*
vendors:
  - C-Prot
products:
  - C-Prot AppDefense (< 1.0.2729)
cves:
  - id: CVE-2026-95648
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95648
---

C-Prot AppDefense is affected by an improperly controlled modification of dynamically-determined object attributes vulnerability, which allows for privilege escalation. This issue affects C-Prot AppDefense versions before 1.0.2729.
