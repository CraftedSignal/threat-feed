---
brief_id: brief-2026-11-09-pardus-boot-repair-injection
event_id: brief-2026-11-09-pardus-boot-repair-injection
revision: 1
activity_at: "2026-11-09T15:50:26Z"
title: 'Pardus Boot Repair: OS Command Injection (CVE-2026-94434)'
slug: 2026-11-pardus-boot-repair-injection
description: An OS command injection vulnerability exists in TÜBİTAK BİLGEM Pardus Boot Repair, where improper neutralization of special elements used in an OS command allows OS command injection.
date: "2026-11-09T15:50:26Z"
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
  - cpe:2.3:a:t_bitak_bilgem:pardus_boot_repair:*:*:*:*:*:*:*:*
vendors:
  - TÜBİTAK BİLGEM
products:
  - Pardus Boot Repair (1.0.8 before 1.0.9)
cves:
  - id: CVE-2026-94434
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94434
---

CVE-2026-94434 affects Pardus Boot Repair versions from 1.0.8 before 1.0.9. The vulnerability is caused by improper neutralization of special elements used in an OS command.
