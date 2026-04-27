---
title: Pachno 1.0.6 XML External Entity Injection Vulnerability
slug: 2026-04-pachno-xxe
description: Pachno 1.0.6 is vulnerable to XML external entity injection, allowing unauthenticated attackers to read arbitrary files by injecting malicious XML entities into wiki content due to unsafe XML parsing in the TextParser helper.
date: "2026-04-14T12:00:00Z"
severities:
  - critical
tags:
  - xxe
  - cve-2026-40042
  - pachno
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-40042
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40042
  - https://www.vulncheck.com/advisories/pachno-wiki-textparser-xml-external-entity-injection
  - https://www.zeroscience.mk/en/vulnerabilities/ZSL-2026-5984.php
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect XML External Entity Injection Attempts via URI
    description: Detects potential XML External Entity (XXE) injection attempts by identifying requests containing XML entity declarations in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1566.003
    data_sources:
      - webserver
      - linux
  - title: Detect XML External Entity Injection Attempts via Request Body
    description: Detects potential XML External Entity (XXE) injection attempts by identifying requests containing XML entity declarations in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1566.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Pachno 1.0.6 is susceptible to an XML External Entity (XXE) injection vulnerability, identified as CVE-2026-40042. This flaw resides in the TextParser helper component, where unsafe XML parsing occurs. An unauthenticated attacker can exploit this vulnerability to read arbitrary files from the server. The attack involves injecting malicious XML entities into various parts of the application, including wiki table syntax, issue descriptions, comments, and wiki articles. The vulnerability is…
