---
title: CVE-2026-14713 — SQL Injection in SourceCodester Pizzafy E-Commerce System
slug: 2026-07-pizzafy-sql-injection
description: A critical SQL injection vulnerability (CVE-2026-14713) exists in SourceCodester Pizzafy E-Commerce System version 1.0, allowing unauthenticated remote attackers to execute arbitrary SQL commands by manipulating the 'ID' argument in the `/admin/ajax.php?action=confirm_order` endpoint, potentially leading to data exfiltration or modification, with a public exploit available.
date: "2026-07-05T06:26:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - cve
  - sourcecodester
  - e-commerce
vendors:
  - SourceCodester
products:
  - Pizzafy E-Commerce System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument ID results in sql injection. The attack can be launched remotely. The exploit has been released to the public and may be used for attacks.
    confidence_band: high
cves:
  - id: CVE-2026-14713
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14713
  - https://github.com/J4ng3ay/CVE/issues/1
  - https://vuldb.com/cve/CVE-2026-14713
  - https://vuldb.com/submit/846718
  - https://vuldb.com/vuln/376303
  - https://vuldb.com/vuln/376303/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detects CVE-2026-14713 Exploitation — Pizzafy SQL Injection
    description: Detects exploitation attempts for CVE-2026-14713, an SQL injection vulnerability in SourceCodester Pizzafy E-Commerce System 1.0, by identifying malicious characters in the 'ID' parameter of the `/admin/ajax.php?action=confirm_order` endpoint.
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

A significant security flaw, tracked as CVE-2026-14713, has been identified in the SourceCodester Pizzafy E-Commerce System 1.0. This vulnerability manifests as a remote SQL injection within the `/admin/ajax.php` file, specifically when handling the `ID` argument in the `action=confirm_order` context. Threat actors can exploit this by crafting malicious HTTP requests that embed SQL queries into the `ID` parameter. The flaw allows for unauthenticated remote exploitation, meaning attackers can leverage it without prior access to the system. The existence of a public exploit for this vulnerability elevates the immediate risk, making it critical for organizations using this software to patch or implement protective measures swiftly to prevent potential data breaches, unauthorized data manipulation, or system compromise.

## Attack Chain

1.  Attacker identifies a publicly accessible instance of SourceCodester Pizzafy E-Commerce System 1.0.
2.  Attacker crafts a specially designed HTTP GET request targeting the `/admin/ajax.php` endpoint.
3.  The request includes the `action=confirm_order` parameter and a malicious SQL payload embedded within the `ID` argument (e.g., `ID=1 UNION SELECT @@version, user(), database()`).
4.  The vulnerable application processes this request, failing to properly sanitize the `ID` parameter, and executes the attacker-supplied SQL query against its backend database.
5.  The database management system (DBMS) processes the injected query and returns the results within the legitimate HTTP response from the web server.
6.  Attacker parses the web server's response to extract sensitive information, such as database schema, user credentials, system configuration, or other confidential data.
7.  The attacker continues to refine payloads to further exfiltrate, modify, or potentially corrupt data within the database, ultimately achieving data compromise.

## Impact

Successful exploitation of CVE-2026-14713 can lead to severe consequences for organizations utilizing SourceCodester Pizzafy E-Commerce System 1.0. As a remote SQL injection vulnerability, attackers can gain unauthorized access to the underlying database. This typically results in full data compromise, including exfiltration of sensitive customer data (names, addresses, payment information), administrative credentials, and other proprietary business data. Attackers could also tamper with order details, pricing, inventory, or user accounts, causing financial losses, reputational damage, and operational disruption. While the source does not specify victim count or targeted sectors, any organization deploying this specific version of the e-commerce system is at high risk.

## Recommendation

*   Immediately patch SourceCodester Pizzafy E-Commerce System 1.0 to a non-vulnerable version if available.
*   Deploy the Sigma rule "Detects CVE-2026-14713 Exploitation — Pizzafy SQL Injection" to your SIEM/WAF and tune for your environment.
*   Enable comprehensive web server logging (category `webserver`) to capture `cs-uri-stem`, `cs-uri-query`, and `cs-method` for detailed forensic analysis.
