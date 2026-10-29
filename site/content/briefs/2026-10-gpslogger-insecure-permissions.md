---
brief_id: brief-2026-10-29-gpslogger-insecure-permissions
event_id: brief-2026-10-29-gpslogger-insecure-permissions
revision: 1
activity_at: "2026-10-29T21:07:53Z"
title: 'mendhak GPSLogger: Insecure permissions (CVE-2026-107047)'
slug: 2026-10-gpslogger-insecure-permissions
description: Insecure permissions in mendhak GPSLogger versionCode 137 allow unauthorized attackers to arbitrarily manipulate the app's logging mechanism and log data.
date: "2026-10-29T21:07:53Z"
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
  - mendhak GPSLogger versionCode 137
cves:
  - id: CVE-2026-107047
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107047
---

CVE-2026-107047 identifies an insecure permissions vulnerability in mendhak GPSLogger versionCode 137. This flaw allows unauthorized attackers to arbitrarily manipulate the application's logging mechanism and log data.
