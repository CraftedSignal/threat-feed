---
brief_id: brief-2026-10-29-nononsense-notes-insecure-permissions
event_id: brief-2026-10-29-nononsense-notes-insecure-permissions
revision: 1
activity_at: "2026-10-29T23:08:33Z"
title: 'NoNonsense Notes: Insecure permissions in NotificationHelper (CVE-2026-107037)'
slug: 2026-10-nononsense-notes-insecure-permissions
description: Insecure permissions in the NotificationHelper component of NoNonsense Notes versionCode 72600 allow unauthorized attackers to write in another user's notes via supplying a note id.
date: "2026-10-29T23:08:33Z"
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
  - NoNonsense Notes (versionCode 72600)
cves:
  - id: CVE-2026-107037
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107037
---

The NotificationHelper component of NoNonsense Notes versionCode 72600 contains an insecure permissions vulnerability. This allows unauthorized attackers to write in another user's notes by supplying a note id.
