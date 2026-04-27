---
title: Perfmatters WordPress Plugin Arbitrary File Overwrite Vulnerability (CVE-2026-4351)
slug: 2026-04-perfmatters-overwrite
description: The Perfmatters plugin for WordPress is vulnerable to arbitrary file overwrite via path traversal, allowing authenticated attackers with subscriber-level access to overwrite arbitrary files on the server with a fixed PHP docblock content, potentially causing denial of service.
date: "2026-04-10T02:37:36Z"
severities:
  - high
tags:
  - wordpress
  - perfmatters
  - file-overwrite
  - path-traversal
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-4351
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4351
rules:
  - title: Detect Perfmatters Arbitrary File Overwrite Attempt
    description: Detects attempts to exploit the Perfmatters plugin arbitrary file overwrite vulnerability (CVE-2026-4351) via suspicious HTTP GET requests.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect File Overwrite via file_put_contents with Traversal
    description: Detects file overwrite attempts using file_put_contents function combined with path traversal, indicative of potential exploitation of vulnerabilities like CVE-2026-4351.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Perfmatters plugin for WordPress, in versions up to and including 2.5.9, is vulnerable to an arbitrary file overwrite vulnerability (CVE-2026-4351). This vulnerability stems from the `PMCS::action_handler()` method's processing of bulk `activate`/`deactivate` actions without proper authorization checks or nonce verification. The unsanitized `$_GET['snippets'][]` values are then passed to `Snippet::activate()`/`Snippet::deactivate()`, which subsequently call `Snippet::update()` and…
