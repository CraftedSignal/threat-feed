---
title: Piwigo SQL Injection Vulnerability (CVE-2026-27834)
slug: 2026-04-piwigo-sql-injection
description: A SQL Injection vulnerability (CVE-2026-27834) exists in Piwigo versions prior to 16.3.0, allowing authenticated administrators to execute arbitrary SQL commands via the pwg.users.getList Web Service API method.
date: "2026-04-03T22:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - piwigo
  - sql-injection
  - cve-2026-27834
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27834
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27834
  - https://github.com/Piwigo/Piwigo/commit/9df471f16243371dc3725c5262e1632d23c8218a
  - https://github.com/Piwigo/Piwigo/security/advisories/GHSA-5jwg-cr5q-vjq2
  - https://piwigo.org/release-16.3.0
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Piwigo SQL Injection Attempt via pwg.users.getList API
    description: Detects potential SQL injection attempts targeting the pwg.users.getList API in Piwigo by looking for specific SQL keywords in the filter parameter of POST requests to api.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Piwigo API Access with Suspicious Parameters
    description: Detects access to the Piwigo API with potentially malicious parameters that might indicate an attempted exploit.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Piwigo, an open-source photo gallery application, is vulnerable to SQL injection in versions before 16.3.0. The vulnerability resides in the `pwg.users.getList` Web Service API method.  Specifically, the `filter` parameter is directly concatenated into a SQL query without sufficient sanitization. This allows an authenticated administrator to inject and execute arbitrary SQL commands on the Piwigo server.  Successful exploitation could lead to data exfiltration, modification, or complete compromise of the Piwigo instance.  Version 16.3.0 patches this vulnerability. The vulnerability was reported on April 3rd, 2026.

## Attack Chain

1.  An authenticated administrator logs into the Piwigo web interface.
2.  The administrator crafts a malicious HTTP POST request to the `api.php` endpoint, targeting the `pwg.users.getList` Web Service API method.
3.  The malicious request includes the `filter` parameter containing a SQL injection payload. The payload is designed to exploit the lack of sanitization.
4.  The Piwigo application receives the request and processes the `pwg.users.getList` API call.
5.  The application concatenates the attacker-controlled `filter` parameter directly into a SQL query without proper escaping or sanitization.
6.  The crafted SQL query is executed against the Piwigo database.
7.  The injected SQL code performs unauthorized actions, such as extracting sensitive data, modifying database records, or executing system commands via SQL.
8.  The attacker retrieves the results of the injected SQL query from the HTTP response.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-27834) in Piwigo versions before 16.3.0 can lead to complete compromise of the Piwigo installation. An attacker could potentially access sensitive data such as user credentials, private photos, and system configuration information. The attacker could also modify or delete data, disrupt service, or potentially gain unauthorized access to the underlying server. Given the administrator privilege required for exploitation, the impact is considered significant within the vulnerable Piwigo instance.

## Recommendation

*   Upgrade Piwigo to version 16.3.0 or later to patch CVE-2026-27834 (see references).
*   Deploy the provided Sigma rule to detect exploitation attempts against the `pwg.users.getList` API endpoint.
*   Monitor web server logs for suspicious POST requests to `api.php` containing unusual characters or SQL keywords in the `filter` parameter.
