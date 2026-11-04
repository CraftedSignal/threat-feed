---
brief_id: brief-2026-11-03-cloudclassroom-sql-injection
event_id: brief-2026-11-03-cloudclassroom-sql-injection
revision: 2
activity_at: "2026-11-04T00:47:56Z"
revision_history:
  - revision: 2
    at: "2026-11-04T00:47:56Z"
    checksum: sha256:f64385ddd7ef239c97806218cb8f90c8c330d29e6a3c03b6889e7919c3674da9
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121502&utm_source=rss&utm_medium=rss
title: 'CloudClassroom-PHP-Project: SQL injection in facultydetails.php (CVE-2026-121502)'
slug: 2026-11-cloudclassroom-sql-injection
description: A SQL injection vulnerability exists in the facultydetails.php file of the mathurvishal CloudClassroom-PHP-Project, triggered via the deleteid argument.
date: "2026-11-03T22:18:42Z"
lastmod: "2026-11-04T00:47:14Z"
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
  - cpe:2.3:a:mathurvishal:cloudclassroom_php_project:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-121502&utm_source=rss&utm_medium=rss
vendors:
  - mathurvishal
products:
  - CloudClassroom-PHP-Project
cves:
  - id: CVE-2026-121502
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121502
  - https://sploitus.com/exploit?id=CVE-2026-121502&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-04T00:47:14Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121502&utm_source=rss&utm_medium=rss
---

A vulnerability was identified in the mathurvishal CloudClassroom-PHP-Project. The issue involves an unknown function within facultydetails.php, where manipulation of the deleteid argument leads to SQL injection. The attack may be initiated remotely, and a public exploit is available. The product utilizes a rolling release model, so no specific version information for affected or updated releases is available. The vendor was contacted but did not respond.
