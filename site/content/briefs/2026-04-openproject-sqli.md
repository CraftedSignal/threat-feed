---
title: OpenProject SQL Injection Vulnerability (CVE-2026-34717)
slug: 2026-04-openproject-sqli
description: OpenProject versions before 17.2.3 are susceptible to SQL injection due to improper input sanitization in the '=n' operator, potentially allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-02T18:16:33Z"
severities:
  - critical
tags:
  - openproject
  - sqli
  - cve-2026-34717
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34717
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34717
  - https://github.com/opf/openproject/releases/tag/v17.2.3
  - https://github.com/opf/openproject/security/advisories/GHSA-5rrm-6qmq-2364
ioc_counts:
  email: 1
rules:
  - title: Detect OpenProject SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting OpenProject instances by identifying suspicious patterns in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenProject Version Check via HTTP Request
    description: Detects requests to common OpenProject version check files.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenProject, a web-based project management software, is vulnerable to SQL injection in versions prior to 17.2.3. The vulnerability lies within the `=n` operator located in `modules/reporting/lib/report/operator.rb:177`. This operator improperly handles user input by directly embedding it into SQL WHERE clauses without adequate parameterization. An attacker could leverage this flaw to inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion. The…
