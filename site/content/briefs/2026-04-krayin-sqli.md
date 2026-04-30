---
title: Krayin CRM v2.2.x SQL Injection Vulnerability
slug: 2026-04-krayin-sqli
description: Krayin CRM v2.2.x is vulnerable to SQL injection via the rotten_lead parameter in /Lead/LeadDataGrid.php, potentially allowing attackers to read sensitive data.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-38528
  - krayin-crm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-38528
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38528
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2026-38528
  - https://github.com/krayin/laravel-crm
rules:
  - title: Detect Krayin CRM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the /Lead/LeadDataGrid.php endpoint in Krayin CRM.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Krayin CRM Error Based SQL Injection
    description: Detects error-based SQL injection attempts targeting Krayin CRM.
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

Krayin CRM v2.2.x is susceptible to a SQL injection vulnerability identified as CVE-2026-38528. The vulnerability resides in the `/Lead/LeadDataGrid.php` script, specifically within the `rotten_lead` parameter. An attacker could exploit this vulnerability by injecting malicious SQL queries, potentially gaining unauthorized access to sensitive information stored within the CRM database. The CVSS v3.1 score is 7.1, indicating a high severity level. Successful exploitation requires a low level of privileges. This vulnerability was reported in April 2026 and could impact organizations using the affected Krayin CRM version, leading to data breaches and potential compromise of customer information.

## Attack Chain

1. An attacker identifies a vulnerable Krayin CRM v2.2.x instance.
2. The attacker crafts a malicious HTTP request targeting `/Lead/LeadDataGrid.php`.
3. The HTTP request includes a SQL injection payload within the `rotten_lead` parameter.
4. The Krayin CRM application processes the request without proper sanitization of the `rotten_lead` parameter.
5. The injected SQL query is executed against the CRM database.
6. The attacker retrieves sensitive data from the database, such as customer details, user credentials, or financial information.
7. The attacker may use the compromised data for further malicious activities, such as identity theft or financial fraud.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to the unauthorized disclosure of sensitive customer data, financial records, and internal CRM data. This could result in significant financial losses, reputational damage, and legal repercussions for affected organizations. While the exact number of potential victims is unknown, any organization using Krayin CRM v2.2.x is at risk.

## Recommendation

*   Apply any available patches or updates from the vendor to address CVE-2026-38528.
*   Implement input validation and sanitization on the `rotten_lead` parameter within `/Lead/LeadDataGrid.php` to prevent SQL injection attacks.
*   Deploy the Sigma rule "Detect Krayin CRM SQL Injection Attempt" to your SIEM and tune for your environment.
*   Monitor web server logs for suspicious requests targeting `/Lead/LeadDataGrid.php` with potentially malicious SQL syntax.
*   Implement strong database access controls to limit the impact of successful SQL injection attacks.
