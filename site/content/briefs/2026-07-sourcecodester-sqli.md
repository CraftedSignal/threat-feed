---
title: Critical SQL Injection Vulnerability in SourceCodester Simple and Nice Shopping Cart Script (CVE-2026-15703)
slug: 2026-07-sourcecodester-sqli
description: A critical SQL injection vulnerability, identified as CVE-2026-15703, exists in SourceCodester Simple and Nice Shopping Cart Script version 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'user_id' argument in '/admin/userproductdeletequery.php', with a public exploit enabling unauthorized data access, modification, or deletion.
date: "2026-07-14T19:50:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
vendors:
  - SourceCodester
products:
  - Simple and Nice Shopping Cart Script 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was detected in SourceCodester Simple and Nice Shopping Cart Script 1.0. [...] Performing a manipulation of the argument user_id results in sql injection. It is possible to initiate the attack remotely. The exploit is now public and may be used.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (I:L and A:L indicate low integrity and availability impact, which can involve data modification or deletion)
    confidence_band: med
cves:
  - id: CVE-2026-15703
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15703
  - https://github.com/Wut-sys/cve/issues/1
  - https://vuldb.com/cve/CVE-2026-15703
  - https://vuldb.com/submit/856152
  - https://vuldb.com/vuln/378250
  - https://vuldb.com/vuln/378250/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detect CVE-2026-15703 Exploitation - SourceCodester SQLi
    description: Detects CVE-2026-15703 exploitation - SQL injection vulnerability in SourceCodester Simple and Nice Shopping Cart Script 1.0 via the 'user_id' parameter in '/admin/userproductdeletequery.php'.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1485
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL injection vulnerability, identified as CVE-2026-15703, has been discovered in SourceCodester Simple and Nice Shopping Cart Script version 1.0. This flaw specifically affects the `/admin/userproductdeletequery.php` file, where improper handling of the `user_id` argument allows for remote SQL injection. Attackers can manipulate this argument to execute arbitrary SQL commands against the backend database. The vulnerability has a CVSS v3.1 Base Score of 7.3 (High) and is remotely exploitable without authentication. A public exploit for this vulnerability is now available, significantly increasing the risk of widespread exploitation against unpatched systems. This vulnerability enables unauthorized data disclosure, modification, and potentially deletion within the application's database.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP GET request to the vulnerable endpoint `/admin/userproductdeletequery.php` on the target web server.
2. The attacker includes a malicious SQL injection payload within the `user_id` parameter of the URL query string.
3. The vulnerable SourceCodester script processes the `user_id` argument without proper input sanitization or validation before incorporating it into an SQL query.
4. The application's backend database executes the attacker-controlled SQL query, allowing for unauthorized operations beyond the intended functionality.
5. Depending on the payload, the attacker can achieve unauthorized data access (e.g., retrieving sensitive database contents), data modification, or deletion of database records.
6. The web server responds to the attacker, potentially revealing the results of the executed SQL query or confirming the success of the injection, enabling further reconnaissance or impact.

## Impact

Successful exploitation of CVE-2026-15703 can lead to unauthorized access to sensitive data stored in the application's database, including user details, product information, and other confidential records. Attackers could also modify or delete existing data, leading to data integrity issues, defacement, or service disruption. The public availability of an exploit significantly lowers the bar for attackers, increasing the likelihood of widespread attacks against vulnerable SourceCodester Simple and Nice Shopping Cart Script 1.0 installations. While the CVSS v3.1 score indicates low impact on confidentiality, integrity, and availability (C:L, I:L, A:L), SQL injection can often enable more severe consequences such as full database compromise or, in some cases, remote code execution.

## Recommendation

* Prioritize patching or upgrading SourceCodester Simple and Nice Shopping Cart Script to a version that addresses CVE-2026-15703 immediately.
* Deploy the Sigma rule "Detect CVE-2026-15703 Exploitation - SourceCodester SQLi" to your SIEM and tune for your environment to identify exploitation attempts.
* Implement web application firewalls (WAFs) with rules to detect and block common SQL injection patterns, specifically targeting the `/admin/userproductdeletequery.php` endpoint and the `user_id` parameter.
* Enable comprehensive logging for web servers to capture detailed HTTP request information, including full URI and query parameters, to aid in detection and forensic analysis related to `category: webserver` logs.
