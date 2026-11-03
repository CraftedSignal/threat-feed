---
brief_id: brief-2026-11-03-axxonsoft-default-password
event_id: brief-2026-11-03-axxonsoft-default-password
revision: 1
activity_at: "2026-11-03T22:18:54Z"
title: 'AxxonSoft Axxon One: Unauthorized Access via Default Administrator Credentials (CVE-2026-121022)'
slug: 2026-11-axxonsoft-default-password
description: A vulnerability (CVE-2026-121022) exists in the web client of AxxonSoft Axxon One before 3.0.0 on Windows and Linux where the system fails to enforce a mandatory password change for the default administrator account, allowing remote unauthenticated access.
date: "2026-11-03T22:18:54Z"
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
products:
  - AxxonSoft Axxon One (< 3.0.0)
cves:
  - id: CVE-2026-121022
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121022
---

AxxonSoft Axxon One before 3.0.0 contains a vulnerability (CWE-1393) where the web client does not enforce a mandatory change of the default password on first login for newly installed systems. This allows a remote unauthenticated attacker to log in as the built-in administrator using default credentials. The vulnerability carries a CVSS v3.1 Base Score of 8.1.
