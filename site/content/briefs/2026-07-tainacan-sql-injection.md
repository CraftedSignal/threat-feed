---
title: 'CVE-2026-6230: Tainacan WordPress Plugin SQL Injection Vulnerability'
slug: 2026-07-tainacan-sql-injection
description: An unauthenticated attacker can exploit CVE-2026-6230, a time-based blind SQL Injection vulnerability in the Tainacan plugin for WordPress (versions up to and including 1.0.3) via the 'geoquery' parameter, to append arbitrary SQL queries and exfiltrate sensitive information from the database due to insufficient input validation.
date: "2026-07-08T12:25:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - sql-injection
  - webserver
  - vulnerability
  - cve
vendors:
  - Tainacan
  - WordPress
products:
  - Tainacan plugin (< 1.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Tainacan plugin for WordPress is vulnerable to time-based blind SQL Injection via the 'geoquery' parameter in all versions up to and including 1.0.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.
    confidence_band: high
cves:
  - id: CVE-2026-6230
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6230
  - https://github.com/tainacan/tainacan/commit/579d28d7752b27ed3407f5197abb6349b3efc3c9
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/241d9cd3-9331-49b2-8083-dc646070488e?source=cve
rules:
  - title: Detect CVE-2026-6230 Exploitation - Tainacan Plugin SQL Injection
    description: Detects CVE-2026-6230 exploitation - SQL Injection attempts in the 'geoquery' parameter of the Tainacan WordPress plugin, looking for common time-based blind SQLi patterns.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-6230 details a critical time-based blind SQL Injection vulnerability impacting the Tainacan plugin for WordPress, affecting all versions up to and including 1.0.3. This flaw originates from inadequate sanitization and escaping of user-supplied input to the 'geoquery' parameter, coupled with insufficient preparation of the underlying SQL query. The vulnerability allows unauthenticated attackers to inject malicious SQL code, thereby extending existing database queries. This enables attackers to systematically extract sensitive data from the WordPress database, potentially compromising user credentials, content, and configuration information. The severity is rated with a CVSS 3.1 Base Score of 7.5 (High), emphasizing the significant risk of data confidentiality loss.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running a vulnerable version (<= 1.0.3) of the Tainacan plugin.
2. The attacker sends an HTTP GET or POST request to the vulnerable WordPress site, targeting an endpoint that processes the `geoquery` parameter.
3. The attacker crafts a malicious `geoquery` parameter containing time-based blind SQL injection payloads, such as `SLEEP()` or `BENCHMARK()`, designed to introduce delays in database responses based on logical conditions.
4. The Tainacan plugin insecurely concatenates the attacker-supplied `geoquery` input directly into an SQL statement without proper escaping or parameterized queries.
5. The database server executes the malformed SQL query, causing a noticeable delay in the HTTP response if the injected conditional statement evaluates to true.
6. By iteratively modifying the injected SQL payload and observing the server's response times, the attacker can infer characters, one by one, to systematically exfiltrate sensitive data (e.g., user hashes, API keys, intellectual property) from the database.

## Impact

Successful exploitation of CVE-2026-6230 allows unauthenticated attackers to perform time-based blind SQL injection, leading to the exfiltration of sensitive information from the database. This could include administrator credentials, user data, private content, and site configuration details. The lack of authentication required for exploitation means a wide range of WordPress sites utilizing the Tainacan plugin are at risk. The primary damage is to data confidentiality, which can result in significant reputational harm, regulatory fines, and further compromise of the affected organization's systems.

## Recommendation

* Immediately update the Tainacan plugin for WordPress to version 1.0.4 or higher to patch CVE-2026-6230, which includes commit `579d28d7752b27ed3407f5197abb6349b3efc3c9`.
* Deploy the Sigma rule "Detect CVE-2026-6230 Exploitation - Tainacan Plugin SQL Injection" to your SIEM to detect attempts to exploit this vulnerability.
* Enable comprehensive webserver logging (e.g., Apache access logs, Nginx access logs) to capture full URI and query string details for `webserver` category rules.
