---
brief_id: brief-2026-10-31-the-project-manager-rce
event_id: brief-2026-10-31-the-project-manager-rce
revision: 2
activity_at: "2026-11-03T14:11:15Z"
revision_history:
  - revision: 2
    at: "2026-11-03T14:11:15Z"
    checksum: sha256:e644bb3a6dd679620087e8722675af2e2fab1c1de9247ebda46eda28ed0288a4
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=015868AD-B5AF-5B19-8F72-0485181E44AE&utm_source=rss&utm_medium=rss
title: 'The Project Manager WordPress Plugin: Unauthenticated Remote Code Execution (CVE-2026-116512)'
slug: 2026-10-the-project-manager-rce
description: The Project Manager - AI Powered Project Management, Task Management, Kanban Board & Time Tracker plugin for WordPress contains a remote code execution vulnerability in versions up to and including 4.1.1.
date: "2026-10-31T09:54:08Z"
lastmod: "2026-11-03T14:10:40Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:a:wedevs:project_manager:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=015868AD-B5AF-5B19-8F72-0485181E44AE&utm_source=rss&utm_medium=rss
vendors:
  - weDevs
products:
  - Project Manager (<= 4.1.1)
cves:
  - id: CVE-2026-116512
    cvss: 9.8
    epss: 0.00584
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116512
  - https://sploitus.com/exploit?id=015868AD-B5AF-5B19-8F72-0485181E44AE&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T14:10:40Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=015868AD-B5AF-5B19-8F72-0485181E44AE&utm_source=rss&utm_medium=rss
---

The vulnerability exists in the 'id' parameter, where unsanitized input is concatenated into a pipe-delimited validation rule string. This string is split and each token is invoked as a dynamic PHP function without an allowlist. Because the validation occurs via the WordPress REST API before the permission check, unauthenticated attackers can execute arbitrary code on the server.
