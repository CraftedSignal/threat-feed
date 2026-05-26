---
title: Joomla! Ek Rishta Component 2.10 SQL Injection Vulnerability
slug: 2026-05-joomla-ek-rishta-sqli
description: Joomla! Component Ek Rishta version 2.10 is vulnerable to SQL injection allowing unauthenticated attackers to manipulate database queries by injecting SQL code via the cid parameter through GET requests to the user_detail view, potentially extracting sensitive database information.
date: "2026-05-26T13:40:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - joomla
  - vulnerability
vendors:
  - Joomla!
products:
  - Ek Rishta 2.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25348
    cvss: 8.2
    epss: 0.00068
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25348
rules:
  - title: Detects CVE-2018-25348 Exploitation — Joomla Ek Rishta SQL Injection Attempt
    description: Detects CVE-2018-25348 exploitation — An unauthenticated attacker attempts to exploit an SQL injection vulnerability in Joomla! Ek Rishta by injecting SQL code into the `cid` parameter of a GET request to `/index.php`
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2018-25348 Exploitation — Joomla Ek Rishta SQL Injection Response Code
    description: Detects CVE-2018-25348 exploitation — Monitors for HTTP 500 response codes when accessing the user_detail view, possibly due to a failed SQL injection attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Joomla! Component Ek Rishta 2.10 is susceptible to an SQL injection vulnerability that enables unauthenticated attackers to execute arbitrary SQL commands. This flaw allows attackers to manipulate database queries by injecting SQL code through the `cid` parameter in GET requests to the `user_detail` view. Successful exploitation could lead to unauthorized access to sensitive database information. The vulnerability was reported in the Ek Rishta component, a Joomla! extension. Attackers can leverage this vulnerability without authentication, making it a critical risk for systems running the affected component.

## Attack Chain

1. An unauthenticated attacker identifies a Joomla! website using Ek Rishta 2.10.
2. The attacker crafts a malicious GET request targeting the `user_detail` view.
3. The attacker injects SQL code into the `cid` parameter of the GET request.
4. The Joomla! application processes the crafted request without proper sanitization of the `cid` parameter.
5. The injected SQL code is executed against the database.
6. The attacker retrieves sensitive database information, such as user credentials or configuration details.
7. The attacker may further compromise the system by using the extracted credentials or exploiting other vulnerabilities.

## Impact

Successful exploitation of this vulnerability can lead to the disclosure of sensitive information stored in the database, potentially including user credentials, personal data, and other confidential information. This can result in identity theft, financial fraud, and reputational damage to the affected organization. Given the unauthenticated nature of the vulnerability, any Joomla! website using the vulnerable component is at risk.

## Recommendation

- Apply the patch or upgrade to a non-vulnerable version of Ek Rishta to remediate CVE-2018-25348.
- Deploy the Sigma rule provided in this brief to detect exploitation attempts targeting the `cid` parameter in `user_detail` GET requests.
- Implement input validation and sanitization measures to prevent SQL injection vulnerabilities in web applications.
- Review web server logs for suspicious GET requests targeting the `user_detail` view with potentially malicious SQL code in the `cid` parameter.
