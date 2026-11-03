---
brief_id: brief-2026-11-03-buddyboss-upload
event_id: brief-2026-11-03-buddyboss-upload
revision: 2
activity_at: "2026-11-03T16:15:50Z"
revision_history:
  - revision: 2
    at: "2026-11-03T16:15:50Z"
    checksum: sha256:724848d5ea23940cdb2a57dfa8d88965cbab7f5e4082a0876231645f25773718
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-76124&utm_source=rss&utm_medium=rss
title: 'BuddyBoss App: Arbitrary File Upload in send_feedback function (CVE-2026-76124)'
slug: 2026-11-buddyboss-upload
description: The BuddyBoss App WordPress plugin (all versions up to and including 3.2.1) is vulnerable to Arbitrary File Upload via the send_feedback function, which may lead to remote code execution.
date: "2026-11-03T13:57:14Z"
lastmod: "2026-11-03T16:15:03Z"
type: advisory
claim_state: <nil>
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-76124&utm_source=rss&utm_medium=rss
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
  - https://sploitus.com/exploit?id=CVE-2026-76124&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T16:15:03Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-76124&utm_source=rss&utm_medium=rss
---

The BuddyBoss App plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to and including 3.2.1 via the send_feedback function. The vulnerability arises from insufficient file type validation that relies on the client-supplied Content-Type header. Authenticated users with subscriber-level access and above can upload executable files. While files are intended to be deleted after transmission, a race condition during SMTP execution or a failure of the wp_mail() function can allow files to persist on the server.
