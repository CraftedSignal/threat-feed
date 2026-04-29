---
title: PilusCart 1.4.1 SQL Injection Vulnerability
slug: 2026-04-piluscart-sqli
description: PilusCart 1.4.1 is vulnerable to SQL injection, allowing unauthenticated attackers to manipulate database queries by injecting SQL code through the 'send' parameter to extract sensitive database information.
date: "2026-04-05T21:16:44Z"
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
  - id: CVE-2019-25672
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25672
  - https://sourceforge.net/projects/pilus/
  - https://www.exploit-db.com/exploits/46368
  - https://www.vulncheck.com/advisories/piluscart-sql-injection-via-send-parameter
rules:
  - title: Detect PilusCart SQL Injection Attempt via Send Parameter
    description: Detects potential SQL injection attempts in PilusCart 1.4.1 via the 'send' parameter in POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PilusCart Exploitation Attempts via Exploit-DB Payload
    description: Detects potential exploitation attempts against PilusCart by identifying specific payloads found in Exploit-DB.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PilusCart 1.4.1 is susceptible to a SQL injection vulnerability (CVE-2019-25672) that allows unauthenticated attackers to inject malicious SQL code via the 'send' parameter. This vulnerability enables attackers to manipulate database queries, potentially leading to the extraction of sensitive information. The attack involves crafting malicious POST requests to the comment submission endpoint using RLIKE-based boolean SQL injection techniques. Successful exploitation grants attackers unauthorized access to the database, impacting confidentiality and potentially integrity. Defenders need to implement robust input validation and sanitization measures to mitigate this risk.

## Attack Chain

1.  An unauthenticated attacker identifies the comment submission endpoint in PilusCart 1.4.1.
2.  The attacker crafts a malicious POST request targeting the comment submission endpoint.
3.  The POST request includes a SQL injection payload within the 'send' parameter.
4.  The payload utilizes RLIKE-based boolean SQL injection to bypass input validation.
5.  The application processes the malicious POST request without proper sanitization of the 'send' parameter.
6.  The injected SQL code is executed within the context of the database query.
7.  The attacker extracts sensitive data from the database through boolean-based inference.
8.  The attacker gains unauthorized access to sensitive information, such as user credentials or financial data.

## Impact

Successful exploitation of the SQL injection vulnerability (CVE-2019-25672) in PilusCart 1.4.1 can lead to the unauthorized disclosure of sensitive data, potentially affecting all users and customers of the vulnerable application. While the number of victims is currently unknown, the impact could be significant depending on the sensitivity of the data stored in the database. This vulnerability can lead to data breaches, financial losses, and reputational damage for organizations using the affected PilusCart version.

## Recommendation

*   Deploy the Sigma rule `Detect PilusCart SQL Injection Attempt via Send Parameter` to detect malicious POST requests targeting the comment submission endpoint (log source: webserver).
*   Implement input validation and sanitization on the 'send' parameter to prevent SQL injection attacks (reference: CVE-2019-25672).
*   Upgrade to a patched version of PilusCart that addresses the SQL injection vulnerability (reference: CVE-2019-25672).
*   Monitor web server logs for suspicious POST requests with RLIKE-based SQL injection payloads in the 'send' parameter (log source: webserver).
