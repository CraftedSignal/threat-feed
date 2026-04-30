---
title: SQL Injection Vulnerability in Lost and Found Thing Management 1.0
slug: 2026-04-lost-found-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-6163) exists in code-projects Lost and Found Thing Management 1.0 via manipulation of the 'cat' parameter in /catageory.php, potentially allowing attackers to read, modify, or delete database information.
date: "2026-04-13T06:16:06Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6163
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6163
  - https://code-projects.org/
  - https://github.com/lanPwa/CVE/issues/2
  - https://vuldb.com/submit/797088
  - https://vuldb.com/vuln/357051
  - https://vuldb.com/vuln/357051/cti
rules:
  - title: Detect Suspicious SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts targeting the /catageory.php endpoint by looking for common SQL keywords in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt via POST Request
    description: Detects potential SQL injection attacks via POST requests by identifying SQL keywords in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical SQL injection vulnerability has been identified in code-projects Lost and Found Thing Management version 1.0, tracked as CVE-2026-6163. This vulnerability resides within the `/catageory.php` file and can be exploited by remotely manipulating the `cat` parameter. Due to the application's failure to properly sanitize user-supplied input, an attacker can inject arbitrary SQL code, potentially leading to unauthorized data access, modification, or deletion. The existence of a publicly available exploit increases the risk of widespread exploitation. Organizations using this software should take immediate action to mitigate the risk.

## Attack Chain

1.  An attacker identifies a vulnerable instance of Lost and Found Thing Management 1.0.
2.  The attacker crafts a malicious HTTP GET request targeting the `/catageory.php` endpoint.
3.  The crafted request includes a SQL injection payload within the `cat` parameter.
4.  The web server receives the request and passes the unsanitized `cat` parameter to the application's database query.
5.  The injected SQL code is executed within the database context.
6.  Depending on the injected code, the attacker can read sensitive data, modify existing records, or delete information from the database.
7.  The database server processes the malicious SQL query and returns the output.
8.  The application returns the modified output to the attacker.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-6163) could allow a remote attacker to compromise the affected Lost and Found Thing Management 1.0 application. This may lead to unauthorized access to sensitive information stored within the database, such as user credentials, personal details of individuals who have lost or found items, and information about the items themselves. The attacker can potentially modify or delete records, leading to data corruption or denial of service. Due to the availability of a public exploit, the potential impact is significant for any organization running this vulnerable software.

## Recommendation

*   Apply available patches or updates provided by the vendor (code-projects.org) to remediate the SQL injection vulnerability in `/catageory.php` as soon as they become available.
*   Implement input validation and sanitization on all user-supplied data, particularly the `cat` parameter in `/catageory.php`, to prevent SQL injection attacks.
*   Deploy the Sigma rule "Detect Suspicious SQL Injection Attempts via URI" to detect potential exploitation attempts against the `/catageory.php` endpoint.
*   Review and restrict database user privileges to follow the principle of least privilege, limiting the impact of successful SQL injection attacks.
*   Monitor web server logs for suspicious activity related to the `/catageory.php` endpoint, such as unusual characters or SQL keywords in the `cat` parameter.
