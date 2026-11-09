---
brief_id: brief-2026-11-09-dynamiapps-privilege-escalation
event_id: brief-2026-11-09-dynamiapps-privilege-escalation
revision: 1
activity_at: "2026-11-09T05:28:57Z"
title: 'DynamiApps Frontend Admin: Incorrect Privilege Assignment (CVE-2026-119506)'
slug: 2026-11-dynamiapps-privilege-escalation
description: An Incorrect Privilege Assignment vulnerability in the acf-frontend-form-element component of DynamiApps Frontend Admin allows for Privilege Escalation.
date: "2026-11-09T05:28:57Z"
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
  - Frontend Admin by DynamiApps (n/a through 3.30.1)
cves:
  - id: CVE-2026-119506
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119506
---

CVE-2026-119506 identifies an Incorrect Privilege Assignment vulnerability in DynamiApps Frontend Admin (specifically the acf-frontend-form-element component). This vulnerability allows Privilege Escalation and affects versions from n/a through 3.30.1.
