---
title: Joomla eXtroForms SQL Injection Vulnerability (CVE-2018-25380)
slug: 2026-05-joomla-extroforms-sqli
description: Joomla Component eXtroForms 2.1.5 contains an SQL injection vulnerability (CVE-2018-25380) that allows authenticated attackers to execute arbitrary SQL commands via crafted POST requests, potentially leading to sensitive data exposure.
date: "2026-05-26T14:17:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - joomla
  - cve-2018-25380
vendors:
  - Joomla
products:
  - eXtroForms 2.1.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25380
    cvss: 7.1
    epss: 0.00026
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25380
  - https://extensions.joomla.org/extensions/extension/contacts-and-feedback/contact-forms/extroforms/
  - https://extro.media/
  - https://www.exploit-db.com/exploits/45472
  - https://www.vulncheck.com/advisories/joomla-component-extroforms-sql-injection-via-filter-parameters
rules:
  - title: Detect Joomla eXtroForms SQL Injection Attempt (CVE-2018-25380)
    description: Detects CVE-2018-25380 exploitation — SQL injection attempts in Joomla eXtroForms component via POST requests to extroformfield view.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Joomla eXtroForms SQL Injection Attempt via filter_type_id (CVE-2018-25380)
    description: Detects CVE-2018-25380 exploitation — SQL injection attempt in Joomla eXtroForms via filter_type_id parameter in POST request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2018-25380 identifies an SQL injection vulnerability within the eXtroForms component version 2.1.5 for Joomla. Authenticated attackers can exploit this flaw by sending malicious POST requests to the `extroformfield` view. The vulnerability lies in the insufficient sanitization of the `filter_type_id`, `filter_pid_id`, and `filter_search` parameters. Successful exploitation allows attackers to inject arbitrary SQL commands, potentially enabling them to extract sensitive database information and server details. This can lead to a significant compromise of the Joomla application and its underlying data.

## Attack Chain

1. An attacker authenticates to the Joomla application.
2. The attacker crafts a malicious POST request targeting the `extroformfield` view.
3. The POST request includes SQL injection payloads within the `filter_type_id`, `filter_pid_id`, or `filter_search` parameters.
4. The eXtroForms component processes the request without proper sanitization of the input.
5. The injected SQL code is executed against the Joomla database.
6. The attacker retrieves sensitive information such as user credentials, configuration data, or other stored data.
7. The attacker may further leverage the SQL injection to modify data within the database.
8. The attacker gains unauthorized access to the Joomla application and/or the underlying server.

## Impact

Successful exploitation of CVE-2018-25380 can lead to the exposure of sensitive data stored within the Joomla application's database. This includes user credentials, personal information, and potentially confidential business data. An attacker could also modify or delete data, leading to data loss or corruption. The high CVSS score of 7.1 reflects the potential for significant impact due to unauthorized data access and modification.

## Recommendation

*   Apply available patches or updates for the eXtroForms component to address CVE-2018-25380.
*   Deploy the Sigma rule `Detect Joomla eXtroForms SQL Injection Attempt (CVE-2018-25380)` to identify potentially malicious POST requests.
*   Implement input validation and sanitization measures to prevent SQL injection vulnerabilities in Joomla components.
*   Monitor web server logs for suspicious POST requests to the `extroformfield` view, as described in the rule's `logsource` block.
*   Review and restrict database user privileges to minimize the impact of successful SQL injection attacks.
