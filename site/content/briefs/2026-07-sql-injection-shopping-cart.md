---
title: 'CVE-2026-14652: SQL Injection in SourceCodester Simple and Nice Shopping Cart Script'
slug: 2026-07-sql-injection-shopping-cart
description: A critical SQL injection vulnerability (CVE-2026-14652) exists in the Admin Login component of SourceCodester Simple and Nice Shopping Cart Script version 1.0, allowing an unauthenticated attacker to remotely exploit it by manipulating the 'Username' argument in the /admin/login.php file, potentially leading to unauthorized access, information disclosure, or data manipulation, with a public exploit available.
date: "2026-07-04T21:18:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - cve
  - initial-access
vendors:
  - SourceCodester
products:
  - Simple and Nice Shopping Cart Script 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was found in SourceCodester Simple and Nice Shopping Cart Script 1.0. This affects an unknown function of the file /admin/login.php of the component Admin Login. The manipulation of the argument Username results in sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-14652
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14652
  - https://github.com/Yuesswor/cve/issues/2
  - https://vuldb.com/cve/CVE-2026-14652
  - https://vuldb.com/submit/846692
  - https://vuldb.com/vuln/376165
  - https://vuldb.com/vuln/376165/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detects CVE-2026-14652 Exploitation - SQL Injection in Simple and Nice Shopping Cart Admin Login
    description: Detects CVE-2026-14652 exploitation - HTTP POST requests to /admin/login.php containing common SQL injection indicators in the URI query or path, which might reflect POST body content or malformed requests.
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

A significant SQL injection vulnerability, tracked as CVE-2026-14652, has been discovered in SourceCodester Simple and Nice Shopping Cart Script version 1.0. This flaw specifically affects the `Admin Login` component, residing in the `/admin/login.php` file. An unauthenticated remote attacker can exploit this by crafting a malicious input to the `Username` argument. Successful exploitation could grant the attacker unauthorized access to the application, allow for information disclosure from the underlying database, or enable data manipulation, impacting the confidentiality, integrity, and availability of the system. The vulnerability has been publicly disclosed, increasing the likelihood of widespread exploitation attempts by malicious actors against unpatched instances. This poses a significant risk to organizations using this shopping cart script.

## Attack Chain

1.  An unauthenticated attacker initiates an HTTP POST request targeting the vulnerable `/admin/login.php` endpoint of the SourceCodester Simple and Nice Shopping Cart Script.
2.  The attacker crafts a malicious SQL injection payload and inserts it into the `Username` parameter within the POST request body.
3.  The web application receives the request and processes the `Username` argument without adequate input sanitization or validation.
4.  The application concatenates the malicious input directly into an SQL query intended for database authentication.
5.  The database server executes the malformed SQL query, which may bypass authentication checks, return sensitive data, or modify database records.
6.  Upon successful SQL injection, the attacker gains unauthorized administrative access to the shopping cart application.
7.  The attacker can then exfiltrate sensitive customer and order data, modify product information, or potentially compromise other parts of the system.

## Impact

The successful exploitation of CVE-2026-14652 can lead to severe consequences for organizations utilizing SourceCodester Simple and Nice Shopping Cart Script 1.0. Given that the vulnerability resides in the admin login portal, an attacker could gain complete control over the shopping cart system. This includes unauthorized access to sensitive customer information (names, addresses, payment details if stored), full control over product listings, order management, and potentially the ability to inject malicious code into the website affecting end-users. The public disclosure of the exploit increases the risk of widespread automated attacks, potentially leading to data breaches, reputational damage, and operational disruption for affected businesses.

## Recommendation

*   Immediately patch SourceCodester Simple and Nice Shopping Cart Script to a version where CVE-2026-14652 is resolved or remove the affected version if no patch is available.
*   Deploy a Web Application Firewall (WAF) in front of web servers hosting the application and ensure WAF rules for SQL injection detection and prevention are enabled and actively blocking requests targeting `/admin/login.php`.
*   Monitor web server access logs for requests to `/admin/login.php` containing unusual characters, SQL keywords, or multiple authentication failures, which may indicate exploitation attempts for CVE-2026-14652.
*   Deploy the provided Sigma rule to your SIEM to detect exploitation attempts of CVE-2026-14652 by monitoring web server logs.
