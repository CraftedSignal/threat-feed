---
title: eDirectory SQL Injection Vulnerability (CVE-2019-25675)
slug: 2026-04-edirectory-sqli
description: Unauthenticated attackers can exploit SQL injection vulnerabilities in eDirectory (CVE-2019-25675) to bypass administrator authentication and disclose sensitive files.
date: "2026-04-05T21:16:45Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - sqli
  - edirectory
  - cve-2019-25675
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
cves:
  - id: CVE-2019-25675
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25675
  - https://www.edirectory.com/
  - https://www.exploit-db.com/exploits/46423
  - https://www.vulncheck.com/advisories/edirectory-all-versions-sql-injection-authentication-bypass
rules:
  - title: Detect eDirectory language_file.php File Disclosure
    description: Detects attempts to exploit the file disclosure vulnerability in language_file.php by looking for requests with specific parameters.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - webserver
      - linux
  - title: Detect eDirectory SQL Injection Attempt
    description: Detects potential SQL injection attempts against the eDirectory login endpoint by looking for common SQL injection keywords in the key parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2019-25675 describes multiple SQL injection vulnerabilities affecting eDirectory. An unauthenticated attacker can exploit these vulnerabilities to bypass administrator authentication and disclose sensitive files. The vulnerability lies in the `key` parameter of the login endpoint. By injecting SQL code, specifically a UNION-based SQL injection, an attacker can authenticate as an administrator. After successful authentication, the attacker can then exploit file disclosure vulnerabilities in the `language_file.php` script to read arbitrary PHP files from the server, potentially exposing sensitive configuration data or credentials. This vulnerability poses a significant risk as it allows unauthorized access and data exfiltration without requiring any prior authentication.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to the login endpoint of eDirectory.
2. The attacker injects SQL code into the `key` parameter within the request, using a UNION-based SQL injection technique.
3. The eDirectory server improperly processes the SQL injection, allowing the attacker to bypass authentication and gain administrator privileges.
4. The attacker, now authenticated as an administrator, sends a request to the `language_file.php` script.
5. The attacker exploits a file disclosure vulnerability in the `language_file.php` script by manipulating input parameters.
6. The server, due to the vulnerability, reads the arbitrary PHP file specified by the attacker.
7. The server returns the contents of the requested PHP file to the attacker.
8. The attacker analyzes the disclosed PHP file, potentially revealing sensitive information such as database credentials or configuration details.

## Impact

Successful exploitation of CVE-2019-25675 allows unauthenticated attackers to gain complete control over the affected eDirectory instance. This can lead to the exfiltration of sensitive data, including user credentials and configuration information. While the specific number of victims is not stated, the potential impact is high considering the widespread use of eDirectory in various sectors. A successful attack could compromise the confidentiality and integrity of critical systems and data.

## Recommendation

*   Apply available patches or updates for eDirectory to address the SQL injection vulnerabilities described in CVE-2019-25675.
*   Deploy the Sigma rule `Detect eDirectory language_file.php File Disclosure` to detect attempts to exploit the file disclosure vulnerability.
*   Deploy the Sigma rule `Detect eDirectory SQL Injection Attempt` to detect SQL injection attempts against the login endpoint.
*   Monitor web server logs for suspicious requests to the login endpoint (`/login`) and `language_file.php` to identify potential exploitation attempts.
