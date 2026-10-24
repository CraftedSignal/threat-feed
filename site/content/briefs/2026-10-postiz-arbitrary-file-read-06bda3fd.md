---
brief_id: brief-2026-10-24-postiz-arbitrary-file-read-06bda3fd
event_id: brief-2026-10-24-postiz-arbitrary-file-read-06bda3fd
revision: 2
activity_at: "2026-10-24T15:15:31Z"
revision_history:
  - revision: 2
    at: "2026-10-24T15:15:31Z"
    checksum: sha256:c1c63b72a7cba42c9b63c1b7e8d7ac60e133b3955f43958010631a5f8e0df1a7
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
title: 'Postiz: Arbitrary file read via crafted media path (CVE-2026-115932)'
slug: 2026-10-postiz-arbitrary-file-read-06bda3fd
description: Postiz fails to validate media paths during post creation, allowing users to read arbitrary files from the server disk and exfiltrate them via Discord attachments.
date: "2026-10-24T14:17:02Z"
lastmod: "2026-10-24T15:14:57Z"
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
cpes:
  - cpe:2.3:a:gitroom:postiz_app:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
vendors:
  - Gitroom
products:
  - postiz-app
cves:
  - id: CVE-2026-115932
    cvss: 9.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115932
  - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-24T15:14:57Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
---

Postiz is vulnerable to an arbitrary file read (CVE-2026-115932) due to improper input validation. When a post is published, the application treats media paths that are not web addresses as local files on the server's disk without verifying that the file resides within the designated upload directory. An attacker can store a crafted media path with a post to have the publishing worker read an arbitrary file and send it as an attachment to an attacker-controlled Discord server. 

The vulnerability can also be exploited to determine if a file exists on the server and to exhaust backend memory. Because self-registration is open by default, an attacker does not require a pre-existing account to exploit these flaws.
