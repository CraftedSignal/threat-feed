---
title: SQL Injection Vulnerability in anirudhkannan Grocery Store Management System 1.0 (CVE-2025-63939)
slug: 2026-04-grocery-store-sqli
description: A critical SQL injection vulnerability (CVE-2025-63939) exists in the anirudhkannan Grocery Store Management System 1.0, allowing unauthenticated attackers to execute arbitrary SQL queries via the sitem_name POST parameter in /Grocery/search_products_itname.php.
date: "2026-04-14T16:16:33Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - cve-2025-63939
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-63939
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-63939
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2025-63939
iocs:
  - type: url
    value: https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2025-63939
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detecting SQL Injection Attempts via sitem_name Parameter
    description: Detects potential SQL injection attempts targeting the sitem_name parameter in the /Grocery/search_products_itname.php endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting Potential SQL Injection Error Responses
    description: Detects web server responses indicative of SQL injection errors, suggesting potential exploitation attempts.
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

CVE-2025-63939 is a SQL injection vulnerability found in anirudhkannan Grocery Store Management System version 1.0. The vulnerability resides in the `/Grocery/search_products_itname.php` script, specifically related to improper input handling of the `sitem_name` POST parameter. An unauthenticated attacker can exploit this vulnerability by injecting malicious SQL code into the `sitem_name` parameter, potentially leading to unauthorized access to the database, data exfiltration, modification, or even complete system compromise. The vulnerable software is a web application typically deployed on web servers, potentially exposing a wide range of grocery stores and related businesses to this critical flaw. This vulnerability was published on 2026-04-14.

## Attack Chain

1. An attacker identifies an instance of anirudhkannan Grocery Store Management System 1.0 running on a web server.
2. The attacker crafts a malicious HTTP POST request targeting the `/Grocery/search_products_itname.php` endpoint.
3. The crafted POST request includes the `sitem_name` parameter, containing SQL injection payload.
4. The web server receives the malicious request and passes the `sitem_name` value to the vulnerable SQL query without proper sanitization or escaping.
5. The injected SQL code is executed by the database server, allowing the attacker to manipulate the database.
6. The attacker uses SQL injection techniques (e.g., `UNION SELECT`, `SLEEP()`) to extract sensitive data, such as user credentials, product information, or financial records.
7. Depending on database privileges, the attacker could modify existing data (e.g., changing product prices, altering inventory levels) or insert new data (e.g., creating rogue administrator accounts).
8. The attacker achieves complete control over the database, potentially leading to full system compromise, data exfiltration, or denial-of-service.

## Impact

Successful exploitation of CVE-2025-63939 can have severe consequences. An attacker could gain unauthorized access to sensitive customer data, including personal information, payment details, and order history. This can lead to financial losses, reputational damage, and legal liabilities for the affected grocery store. The attacker could also manipulate product information, alter pricing, or disrupt business operations. In a worst-case scenario, the attacker could gain complete control of the database server, leading to full system compromise and significant financial and operational losses. Given the widespread use of vulnerable versions, a large number of grocery stores using this software are potentially at risk.

## Recommendation

*   Apply the necessary patches or updates provided by the vendor to address CVE-2025-63939. If a patch is unavailable, consider implementing a web application firewall (WAF) rule to filter out malicious SQL injection attempts targeting the `/Grocery/search_products_itname.php` endpoint.
*   Deploy the Sigma rule `Detecting SQL Injection Attempts via sitem_name Parameter` to your SIEM to identify potential exploitation attempts.
*   Review and harden database access controls to limit the impact of successful SQL injection attacks.
*   Monitor web server logs for suspicious POST requests to `/Grocery/search_products_itname.php` containing potentially malicious SQL syntax, as detected by `Detecting SQL Injection Attempts via sitem_name Parameter`.
*   Inspect traffic for connections to the URL `https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2025-63939` to identify potential reconnaissance activity.
