---
brief_id: brief-2026-11-03-buddyboss-upload
event_id: brief-2026-11-03-buddyboss-upload
revision: 1
activity_at: "2026-11-03T13:57:14Z"
title: 'BuddyBoss App: Arbitrary File Upload in send_feedback function (CVE-2026-76124)'
slug: 2026-11-buddyboss-upload
description: The BuddyBoss App WordPress plugin (all versions up to and including 3.2.1) is vulnerable to Arbitrary File Upload via the send_feedback function, which may lead to remote code execution.
date: "2026-11-03T13:57:14Z"
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
  - cpe:2.3:a:buddyboss:app:*:*:*:*:*:*:*:*
vendors:
  - BuddyBoss
products:
  - BuddyBoss App (<= 3.2.1)
cves:
  - id: CVE-2026-76124
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln.detail/CVE-2026-76124
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76124
---

The BuddyBoss App plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to and including 3.2.1 via the send_feedback function. The vulnerability arises from insufficient file type validation that relies on the client-supplied Content-Type header. Authenticated users with subscriber-level access and above can upload executable files. While files are intended to be deleted after transmission, a race condition during SMTP execution or a failure of the wp_mail() function can allow files to persist on the server.
