---
brief_id: brief-2026-10-28-ivyforms-rce
event_id: brief-2026-10-28-ivyforms-rce
revision: 2
activity_at: "2026-10-30T23:05:53Z"
revision_history:
  - revision: 2
    at: "2026-10-30T23:05:53Z"
    checksum: sha256:4e34374b2bb4f0ecdb928fb8c8ab1a368470821dde897701b42f2ed9ca99af70
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=0E088B39-334A-5856-81AD-68E4971B7EA2&utm_source=rss&utm_medium=rss
title: 'IvyForms Plugin: Arbitrary file upload vulnerability (CVE-2026-109384)'
slug: 2026-10-ivyforms-rce
description: The Innovative Form Builder - IvyForms plugin for WordPress contains an arbitrary file upload vulnerability via the filterFiletypeAndExt function.
date: "2026-10-28T08:27:14Z"
lastmod: "2026-10-30T23:04:47Z"
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0E088B39-334A-5856-81AD-68E4971B7EA2&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - remote-code-execution
  - arbitrary-file-upload
  - cve-2026-109384
vendors:
  - WordPress
cves:
  - id: CVE-2026-109384
    cvss: 8.8
    epss: 0.00725
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109384
  - https://sploitus.com/exploit?id=0E088B39-334A-5856-81AD-68E4971B7EA2&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-30T23:04:47Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0E088B39-334A-5856-81AD-68E4971B7EA2&utm_source=rss&utm_medium=rss
---

The Innovative Form Builder - IvyForms plugin for WordPress is vulnerable to arbitrary file upload in all versions up to, and including, 1.5.1. The vulnerability is caused by insufficient file type validation in the filterFiletypeAndExt function, which overrides native WordPress defenses. An authenticated attacker with 'add_edit_forms' capability or above can configure a form to accept dangerous file extensions, allowing unauthenticated visitors to upload executable files via the /wp-json/ivyforms/v1/form/submission/ REST route, potentially leading to remote code execution.
