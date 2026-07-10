---
title: Vendure Shop API Unauthenticated SQL Injection Vulnerability (CVE-2026-40887)
slug: 2024-01-03-vendure-sqli
description: An unauthenticated SQL injection vulnerability (CVE-2026-40887) exists in the Vendure Shop API affecting PostgreSQL, MySQL/MariaDB, and SQLite databases, where a user-controlled query string parameter is directly interpolated into a raw SQL expression, potentially leading to arbitrary code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vendure
  - sqli
  - cve-2026-40887
  - web-application
  - injection
vendors:
  - Vendure
products:
  - Vendure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40887
    cvss: 9.1
    epss: 0.01762
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40887
rules:
  - title: Detect Vendure Shop API SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the Vendure Shop API via the languageCode parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting Vendure SQLi via Web Logs
    description: Detects SQL injection attempts in Vendure by monitoring HTTP request parameters in web server logs.
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

CVE-2026-40887 is a critical SQL injection vulnerability affecting the Vendure open-source headless commerce platform. Specifically, versions prior to 2.3.4, 3.5.7, and 3.6.2 are vulnerable in the Shop API. This vulnerability allows unauthenticated attackers to inject arbitrary SQL code by manipulating a query string parameter (likely `languageCode`) that is then directly interpolated into a raw SQL expression. Exploitation does not require authentication, posing a significant risk to vulnerable Vendure instances. The vulnerability impacts all supported database backends, including PostgreSQL, MySQL/MariaDB, and SQLite. A hotfix utilizing `RequestContextService.getLanguageCode` has been made available for users unable to upgrade immediately, providing input validation.

## Attack Chain

1.  An attacker identifies a vulnerable Vendure instance running a version prior to 2.3.4, 3.5.7, or 3.6.2.
2.  The attacker crafts a malicious HTTP request targeting the Vendure Shop API.
3.  The crafted request includes a SQL injection payload within the `languageCode` query string parameter.
4.  The vulnerable application code directly interpolates the attacker-controlled `languageCode` parameter into a raw SQL query without proper sanitization or parameterization.
5.  The malicious SQL payload is executed against the database backend (PostgreSQL, MySQL/MariaDB, or SQLite).
6.  The attacker leverages the SQL injection to bypass authentication, extract sensitive data (customer details, credentials, internal configurations), or modify data within the database.
7.  The attacker could potentially use advanced SQL injection techniques to execute operating system commands on the server hosting the database (depending on database configuration and permissions).
8.  Successful exploitation leads to full database compromise, potential server compromise, and significant data breach.

## Impact

Successful exploitation of CVE-2026-40887 can lead to complete database compromise, allowing attackers to steal sensitive customer data, modify product information, or even gain unauthorized access to the underlying server. The impact is especially high due to the unauthenticated nature of the vulnerability, allowing anyone on the internet to potentially exploit it. This can result in significant financial losses, reputational damage, and legal repercussions for affected organizations. The number of potential victims is directly tied to the number of unpatched Vendure instances exposed to the internet.

## Recommendation

*   Immediately upgrade Vendure instances to versions 2.3.4, 3.5.7, or 3.6.2 to patch CVE-2026-40887.
*   If immediate upgrade is not possible, apply the provided hotfix that utilizes `RequestContextService.getLanguageCode` to validate the `languageCode` input as detailed in the advisory.
*   Deploy the Sigma rule "Detect Vendure Shop API SQL Injection Attempts" to your SIEM to identify potential exploitation attempts based on malicious `languageCode` parameters.
*   Monitor web server logs for suspicious HTTP requests targeting the Vendure Shop API with unusual characters or SQL keywords in the query string (as detected by the "Detecting Vendure SQLi via Web Logs" Sigma rule).
