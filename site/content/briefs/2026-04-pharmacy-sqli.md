---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection
slug: 2026-04-pharmacy-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection via the Username parameter in the /ajax.php?action=login endpoint, potentially allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-13T17:16:31Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6189
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6189
rules:
  - title: Detect SQL Injection Attempt in Pharmacy System Login
    description: Detects potential SQL injection attempts targeting the /ajax.php?action=login endpoint by looking for common SQL keywords in the Username parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious SQL Error Messages
    description: Detects SQL error messages that can indicate a possible SQL injection attack in Pharmacy System
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

SourceCodester Pharmacy Sales and Inventory System 1.0 is susceptible to a SQL injection vulnerability (CVE-2026-6189). Disclosed publicly, the flaw resides within the `/ajax.php?action=login` endpoint and can be triggered by manipulating the `Username` parameter. Remote attackers can exploit this vulnerability to potentially execute arbitrary SQL commands, leading to unauthorized data access, modification, or deletion. This vulnerability poses a significant risk to organizations using the affected system, potentially compromising sensitive pharmacy and inventory data.

## Attack Chain

1.  Attacker identifies a vulnerable instance of SourceCodester Pharmacy Sales and Inventory System 1.0.
2.  Attacker crafts a malicious HTTP request targeting the `/ajax.php?action=login` endpoint.
3.  The crafted request includes a SQL injection payload within the `Username` parameter.
4.  The application fails to properly sanitize the `Username` input, passing the malicious payload to the database.
5.  The database executes the injected SQL code, granting the attacker unintended access.
6.  Attacker extracts sensitive information, such as usernames, passwords, or financial data.
7.  The attacker may modify or delete data within the database.
8.  Attacker gains complete control of the application and underlying system, potentially leading to further compromise.

## Impact

A successful SQL injection attack can have severe consequences. Attackers can steal sensitive data, including customer information, prescription details, and financial records. Data modification or deletion can disrupt pharmacy operations, leading to financial losses and reputational damage. The vulnerability affects all instances of SourceCodester Pharmacy Sales and Inventory System 1.0.

## Recommendation

*   Apply patches or updates provided by SourceCodester to address CVE-2026-6189.
*   Implement input validation and sanitization measures to prevent SQL injection attacks on web applications.
*   Deploy the Sigma rule provided in this brief to detect potential SQL injection attempts targeting the `/ajax.php?action=login` endpoint.
*   Monitor web server logs for suspicious activity, such as unusual characters or SQL keywords in request parameters, to identify potential exploitation attempts.
