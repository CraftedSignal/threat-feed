---
title: SQL Injection in Weaver E-cology 8.0
slug: 2026-08-weaver-sql-injection
description: Weaver E-cology 8.0 contains a SQL injection vulnerability in the SignatureDownLoad servlet that allows unauthenticated remote attackers to read arbitrary files via the markId parameter.
date: "2026-08-11T21:49:59Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - cve-2016-20097
  - sql-injection
  - webserver
vendors:
  - Weaver
products:
  - E-cology 8.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Weaver (Fanwei) E-cology 8.0 contains a SQL injection vulnerability in the SignatureDownLoad servlet that allows unauthenticated remote attackers to read arbitrary files
    confidence_band: high
cves:
  - id: CVE-2016-20097
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20097
rules:
  - title: Detects CVE-2016-20097 Exploitation - SQL Injection in SignatureDownLoad
    description: Detects attempts to exploit CVE-2016-20097 by monitoring for SQL injection patterns within the SignatureDownLoad servlet markId parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Weaver (Fanwei) E-cology 8.0 contains a critical SQL injection vulnerability in the SignatureDownLoad servlet. The vulnerability originates from the unsanitized concatenation of the markId GET parameter into a SQL query. An unauthenticated remote attacker can supply a specially crafted UNION SELECT payload via the markId parameter to manipulate the query results. By controlling the markPath value returned by the database, the attacker can force the application to read and stream arbitrary files from the server's filesystem. This allows for the exfiltration of sensitive application configuration files, including those that store database credentials. This vulnerability has been subject to in-the-wild exploitation, with activity observed by the Shadowserver Foundation as early as October 18, 2023. Due to the lack of clear versioning for remediation, all instances of E-cology 8.0 should be treated as potentially vulnerable.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive files from the server filesystem, leading to full application compromise, credential theft, and potentially remote code execution if configuration files or environment variables are leveraged. This poses a significant risk to organizations using the Weaver E-cology platform for business process management.

## Recommendation

Prioritized actions for security teams:
- Identify and inventory all internet-facing instances of Weaver E-cology 8.0.
- Deploy the Sigma rule below to monitor for SQL injection attempts against the SignatureDownLoad servlet.
- Restrict network access to the SignatureDownLoad servlet using a Web Application Firewall (WAF) or equivalent access control list.
- Consult with Weaver vendor support to verify if the deployment has been patched against CVE-2016-20097.
