---
title: Dolibarr ERP-CRM 8.0.4 SQL Injection Vulnerability
slug: 2026-04-dolibarr-sqli
description: Dolibarr ERP-CRM 8.0.4 is vulnerable to SQL injection via the rowid parameter in the admin dict.php endpoint, allowing attackers to execute arbitrary SQL queries and extract sensitive database information.
date: "2026-04-12T13:16:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - cve-2019-25710
  - dolibarr
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25710
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25710
  - https://www.vulncheck.com/advisories/dolibarr-erp-crm-sql-injection-via-rowid-parameter
  - https://www.exploit-db.com/exploits/46095
rules:
  - title: Detect Suspicious Dolibarr rowid Parameter SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the rowid parameter in the Dolibarr admin/dict.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Dolibarr admin/dict.php Access
    description: Detects access to the Dolibarr admin/dict.php endpoint. This can be used to monitor for potential reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Dolibarr ERP-CRM is a popular open-source enterprise resource planning and customer relationship management software. Version 8.0.4 of Dolibarr is susceptible to a critical SQL injection vulnerability (CVE-2019-25710) affecting the `rowid` parameter in the `admin dict.php` endpoint. This flaw allows unauthenticated attackers to inject malicious SQL code through the `rowid` POST parameter. Successful exploitation enables attackers to execute arbitrary SQL queries against the Dolibarr database, potentially leading to the exposure of sensitive information, modification of data, or complete compromise of the application. This vulnerability can be exploited using error-based SQL injection techniques.

## Attack Chain

1.  The attacker identifies a vulnerable Dolibarr ERP-CRM instance running version 8.0.4.
2.  The attacker crafts a malicious HTTP POST request targeting the `admin/dict.php` endpoint.
3.  The request includes the `rowid` parameter containing a SQL injection payload.
4.  The server-side application processes the request and executes the injected SQL code within the database query.
5.  The attacker leverages error-based SQL injection techniques to extract sensitive information from the database, such as user credentials, API keys, or financial data.
6.  The attacker analyzes the error messages returned by the application to refine the SQL injection payload and bypass any security measures.
7.  The attacker potentially uses the extracted credentials to gain unauthorized access to other parts of the application or the underlying system.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to severe consequences, including unauthorized access to sensitive data, data breaches, and complete compromise of the Dolibarr ERP-CRM system. The vulnerability allows attackers to extract sensitive database information, modify data, or potentially execute arbitrary code on the server. Given that ERP and CRM systems often contain critical business data, the impact can be significant for affected organizations.

## Recommendation

*   Apply patches or upgrade to a secure version of Dolibarr ERP-CRM to remediate CVE-2019-25710.
*   Deploy the Sigma rule `Detect Suspicious Dolibarr rowid Parameter SQL Injection Attempt` to your SIEM to identify potential exploitation attempts against the `admin/dict.php` endpoint.
*   Monitor web server logs for unusual POST requests to `admin/dict.php` with suspicious characters or SQL keywords in the `rowid` parameter to detect potential attacks.
*   Implement web application firewall (WAF) rules to filter out malicious SQL injection payloads targeting the `rowid` parameter in `admin/dict.php`.
