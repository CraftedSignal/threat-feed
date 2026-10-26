---
brief_id: brief-2026-10-26-vsolution-matrix-auth-bypass
event_id: brief-2026-10-26-vsolution-matrix-auth-bypass
revision: 1
activity_at: "2026-10-26T15:45:22Z"
title: 'vSolution Matrix: SSH authentication bypass (CVE-2026-59107)'
slug: 2026-10-vsolution-matrix-auth-bypass
description: A shared cryptographic trust configuration in the vSolution Matrix file sharing feature allows unauthorized root access via SSH if the corresponding private key is obtained.
date: "2026-10-26T15:45:22Z"
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
products:
  - vSolution Matrix (main/master station configuration)
cves:
  - id: CVE-2026-59107
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59107
---

A security vulnerability (CVE-2026-59107) has been identified in the vSolution Matrix file sharing feature. A shared cryptographic trust configuration could allow an attacker who obtains the matching private key to authenticate to an affected device via SSH as root. This vulnerability affects only devices configured as a vSolution Matrix main/master station with the file sharing feature enabled.
