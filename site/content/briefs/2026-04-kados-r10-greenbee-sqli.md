---
title: Kados R10 GreenBee SQL Injection Vulnerability (CVE-2019-25702)
slug: 2026-04-kados-r10-greenbee-sqli
description: Kados R10 GreenBee is vulnerable to SQL injection via the id_project parameter, allowing attackers to manipulate database queries to extract sensitive information or modify data.
date: "2026-04-05T21:16:48Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2019-25702
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25702
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25702
  - https://www.vulncheck.com/advisories/kados-r10-greenbee-sql-injection-via-id-project-parameter
rules:
  - title: Detect Suspicious SQL Injection Attempts in Kados R10 GreenBee
    description: Detects potential SQL injection attempts in Kados R10 GreenBee by monitoring HTTP requests containing SQL keywords in the id_project parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Error Based SQL Injection in Kados R10 Greenbee
    description: Detects error-based SQL injection by looking for specific SQL keywords and error messages in HTTP responses.
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

Kados R10 GreenBee is susceptible to SQL injection attacks due to improper input validation of the `id_project` parameter. This vulnerability, identified as CVE-2019-25702, allows a remote attacker to inject arbitrary SQL code into database queries. By crafting malicious requests, an attacker can potentially extract sensitive data, modify existing records, or even gain unauthorized access to the underlying database. The vulnerability was published on April 5, 2026, and poses a significant risk to organizations using affected versions of Kados R10 GreenBee, potentially leading to data breaches and system compromise. Defenders should prioritize patching or mitigating this vulnerability to prevent exploitation.

## Attack Chain

1.  The attacker identifies a Kados R10 GreenBee instance.
2.  The attacker crafts a malicious HTTP request targeting an endpoint that uses the `id_project` parameter in a SQL query.
3.  The attacker injects SQL code into the `id_project` parameter within the crafted HTTP request. For example, `id_project=1' OR '1'='1`.
4.  The Kados R10 GreenBee application processes the request and executes the injected SQL code against the database.
5.  The database server executes the malicious SQL query, potentially returning sensitive information.
6.  The attacker retrieves the extracted data from the application's response.
7.  Depending on the injected SQL code, the attacker may modify database records.
8.  The attacker may gain unauthorized access to the database and perform further malicious actions.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2019-25702) can lead to unauthorized access to sensitive database information, including user credentials, financial data, and other confidential records. This can result in data breaches, financial loss, reputational damage, and legal liabilities for affected organizations. The vulnerability allows attackers to read and modify data, potentially disrupting business operations. The CVSS v3.1 score of 8.2 highlights the severity of this issue.

## Recommendation

*   Apply available patches or upgrades for Kados R10 GreenBee to address CVE-2019-25702.
*   Deploy the Sigma rule `Detect Suspicious SQL Injection Attempts in Kados R10 GreenBee` to your SIEM to detect exploitation attempts by monitoring HTTP request parameters.
*   Implement input validation and sanitization for all user-supplied data, especially for parameters used in database queries, to prevent SQL injection attacks.
*   Monitor web server logs for suspicious activity, such as unusual characters or SQL keywords in the `id_project` parameter of HTTP requests, as shown in the log source for the Sigma rules below.
