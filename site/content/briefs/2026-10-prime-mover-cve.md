---
brief_id: brief-2026-10-24-prime-mover-cve
event_id: brief-2026-10-24-prime-mover-cve
revision: 2
activity_at: "2026-10-24T07:08:43Z"
revision_history:
  - revision: 2
    at: "2026-10-24T07:08:43Z"
    checksum: sha256:42d9fef6e50a4822531e95404411b8c285f140e1c01c608340b14b87d2900d6c
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115806&utm_source=rss&utm_medium=rss
title: 'Prime Mover: Backup and Migration plugin PHP Object Injection (CVE-2026-115806)'
slug: 2026-10-prime-mover-cve
description: The Prime Mover - Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in versions up to and including 2.2.1.
date: "2026-10-24T06:09:00Z"
lastmod: "2026-10-24T07:08:04Z"
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-115806&utm_source=rss&utm_medium=rss
products:
  - Prime Mover - Backup and Migration (<= 2.2.1)
cves:
  - id: CVE-2026-115806
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115806
  - https://sploitus.com/exploit?id=CVE-2026-115806&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-24T07:08:04Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115806&utm_source=rss&utm_medium=rss
---

The Prime Mover - Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 2.2.1. The vulnerability exists due to deserialization of untrusted input in the migration search-and-replace routine (recursiveUnserializeReplace()).

An unauthenticated attacker can store a crafted, base64-encoded serialized object in wp_comments.comment_content through the standard comment-submission endpoint (wp-comments-post.php). When an administrator performs a routine Prime Mover export or restore, the plugin decodes the stored value and passes it to unserialize() without class restrictions. The plugin contains a Property-Oriented Programming (POP) chain within its bundled Freemius library (FS_Clone_Manager::__set → FS_Option_Manager::set_option → store() → update_option()).
