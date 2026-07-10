---
title: WebOfisi E-Ticaret 4.0 SQL Injection Vulnerability (CVE-2018-25210)
slug: 2024-01-webofisi-sqli
description: WebOfisi E-Ticaret 4.0 is vulnerable to SQL injection via the 'urun' GET parameter, allowing unauthenticated attackers to manipulate database queries and execute various SQL injection attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - cve-2018-25210
  - web-ofisi
  - webserver
vendors:
  - WebOfisi
products:
  - WebOfisi E-Ticaret
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25210
  - https://drive.google.com/file/d/1ZghFSsYto-Vpv3PXunx8xm2g-Gs3HJwz/view?usp=sharing
  - https://www.exploit-db.com/exploits/45897
  - https://www.vulncheck.com/advisories/webofisi-e-ticaret-sql-injection-via-urun-parameter
  - https://www.web-ofisi.com
iocs:
  - type: url
    value: https://drive.google.com/file/d/1ZghFSsYto-Vpv3PXunx8xm2g-Gs3HJwz/view?usp=sharing
  - type: url
    value: https://www.exploit-db.com/exploits/45897
  - type: url
    value: https://www.vulncheck.com/advisories/webofisi-e-ticaret-sql-injection-via-urun-parameter
  - type: url
    value: https://www.web-ofisi.com
ioc_counts:
  url: 4
rules:
  - title: WebOfisi E-Ticaret SQL Injection Attempt via urun Parameter
    description: Detects potential SQL injection attempts in WebOfisi E-Ticaret 4.0 via the 'urun' parameter based on common SQL injection syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: WebOfisi E-Ticaret SQL Injection - Error Based
    description: Detects potential error based SQL injection attempts in WebOfisi E-Ticaret 4.0 via the 'urun' parameter, looking for common error-triggering functions.
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

WebOfisi E-Ticaret 4.0 is susceptible to an SQL injection vulnerability (CVE-2018-25210) affecting the 'urun' GET parameter. This vulnerability allows unauthenticated attackers to inject malicious SQL code into database queries. Successful exploitation can lead to unauthorized data access, modification, or deletion. The vulnerability was published on March 26, 2026. Publicly available exploits exist, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to e-commerce platforms using WebOfisi E-Ticaret 4.0, potentially leading to data breaches, financial loss, and reputational damage.

## Attack Chain

1.  An unauthenticated attacker identifies a WebOfisi E-Ticaret 4.0 installation.
2.  The attacker crafts a malicious URL targeting the vulnerable endpoint with a crafted SQL payload in the `urun` GET parameter.
3.  The web server processes the request without proper sanitization of the 'urun' parameter.
4.  The application constructs a SQL query using the attacker-supplied payload.
5.  The database executes the malicious SQL query.
6.  The attacker leverages boolean-based blind, error-based, or time-based blind techniques to extract sensitive data from the database.
7.  The attacker potentially executes stacked queries to modify or delete data within the database.
8.  The attacker gains unauthorized access to sensitive information, modifies website content, or disrupts website functionality.

## Impact

Successful exploitation of this SQL injection vulnerability can have severe consequences. Attackers can gain unauthorized access to sensitive customer data, including personal information, financial details, and order history. This can lead to identity theft, financial fraud, and reputational damage for the affected organization. Attackers could also modify product pricing, manipulate inventory levels, or even inject malicious code into the website, leading to further compromise and potential harm to users.

## Recommendation

*   Apply available patches or upgrade to a secure version of WebOfisi E-Ticaret to address CVE-2018-25210.
*   Deploy the Sigma rule provided below to detect potential exploitation attempts targeting the 'urun' parameter in web server logs.
*   Implement input validation and sanitization measures to prevent SQL injection vulnerabilities.
*   Regularly monitor web server logs for suspicious activity related to SQL injection attempts, focusing on the 'urun' parameter.
*   Block access to the malicious URLs specified in the IOCs at your network perimeter.
