---
brief_id: brief-2026-10-26-heycyan-fileprovider-access
event_id: brief-2026-10-26-heycyan-fileprovider-access
revision: 1
activity_at: "2026-10-26T07:37:08Z"
title: 'HeyCyan App: Improper access control in FileProvider (CVE-2026-116106)'
slug: 2026-10-heycyan-fileprovider-access
description: A security vulnerability in the FileProvider component of HeyCyan App 1.0.103 on Android leads to improper access controls. The vulnerability may be exploited remotely.
date: "2026-10-26T07:37:08Z"
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
  - cpe:2.3:a:heycyan:app:*:*:*:*:*:*:*:*
vendors:
  - HeyCyan
products:
  - HeyCyan App (1.0.103)
affected_os:
  - Android
cves:
  - id: CVE-2026-116106
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116106
---

A security vulnerability has been identified in the FileProvider component of HeyCyan App version 1.0.103 on Android. The issue is characterized by improper access controls that can be manipulated remotely. The vendor did not respond to disclosure attempts.
