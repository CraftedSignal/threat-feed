---
title: Unauthenticated SQL Injection Vulnerability in mb24api Endpoint (CVE-2026-33616)
slug: 2026-04-sql-injection-mb24api
description: CVE-2026-33616 describes an unauthenticated blind SQL Injection vulnerability affecting an mb24api endpoint, which a remote attacker can exploit by injecting special elements into a SQL SELECT command, potentially leading to a total loss of confidentiality due to improper neutralization of special elements.
date: "2026-04-02T10:16:17Z"
severities:
  - critical
tags:
  - sql-injection
  - cve-2026-33616
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33616
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33616
  - https://certvde.com/de/advisories/VDE-2026-030
  - https://mbconnectline.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2026-030.json
rules:
  - title: Detect SQL Injection Attempts via URI Query
    description: Detects potential SQL injection attempts by identifying suspicious SQL syntax in the URI query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts via HTTP POST Body
    description: Detects potential SQL injection attempts by identifying suspicious SQL syntax in the HTTP POST request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33616 identifies a critical security flaw affecting the mb24api endpoint, stemming from an unauthenticated blind SQL Injection vulnerability. The root cause lies in the improper neutralization of special elements within a SQL SELECT command. This vulnerability poses a significant threat, as it allows an unauthenticated remote attacker to inject malicious SQL code. Successful exploitation can result in complete compromise of data confidentiality. Defenders need to be aware of the…
