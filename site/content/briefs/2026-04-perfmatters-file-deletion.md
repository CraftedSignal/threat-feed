---
title: Perfmatters WordPress Plugin Arbitrary File Deletion Vulnerability (CVE-2026-4350)
slug: 2026-04-perfmatters-file-deletion
description: The Perfmatters plugin for WordPress versions up to 2.5.9.1 is vulnerable to arbitrary file deletion via path traversal, allowing authenticated attackers with minimal privileges to delete sensitive files.
date: "2026-04-03T08:16:17Z"
severities:
  - critical
tags:
  - cve-2026-4350
  - wordpress
  - perfmatters
  - file-deletion
  - path-traversal
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-4350
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4350
rules:
  - title: Detect Perfmatters Arbitrary File Deletion Attempt
    description: Detects potential attempts to exploit the Perfmatters arbitrary file deletion vulnerability (CVE-2026-4350) through path traversal sequences in the URI query.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect Perfmatters Arbitrary File Deletion Attempt POST
    description: Detects potential attempts to exploit the Perfmatters arbitrary file deletion vulnerability (CVE-2026-4350) through path traversal sequences in the URI query using POST method.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Perfmatters plugin, a popular WordPress performance optimization tool, contains a critical vulnerability (CVE-2026-4350) affecting versions up to and including 2.5.9.1. This flaw enables authenticated attackers with Subscriber-level access, the lowest privilege level in WordPress, to delete arbitrary files on the server. The vulnerability stems from the `PMCS::action_handler()` method's failure to sanitize the `$_GET['delete']` parameter. This lack of validation allows for path traversal…
