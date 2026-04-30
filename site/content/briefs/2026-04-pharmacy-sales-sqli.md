---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-sales-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection by manipulating the ID argument in the /ajax.php?action=save_receiving file, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-27T06:16:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-7088
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7088
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7088
  - https://github.com/nidieaaa/test/issues/3
  - https://vuldb.com/vuln/359663
rules:
  - title: Detecting SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts in the URI of HTTP requests based on common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting SQL Injection Error Messages
    description: Detects SQL injection attempts by identifying common database error messages in web server responses.
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

SourceCodester Pharmacy Sales and Inventory System version 1.0 is susceptible to SQL injection. The vulnerability resides in the `/ajax.php?action=save_receiving` file, where manipulation of the `ID` argument can lead to arbitrary SQL command execution. This vulnerability allows remote attackers to compromise the application's database. The exploit is publicly available, increasing the risk of exploitation. This vulnerability allows attackers to read, modify, or delete sensitive data, potentially leading to complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable instance of SourceCodester Pharmacy Sales and Inventory System version 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/ajax.php?action=save_receiving` endpoint.
3.  The attacker injects a SQL payload into the `ID` parameter of the request.
4.  The web server processes the request and passes the injected SQL query to the database.
5.  The database executes the malicious SQL query, potentially returning sensitive data to the attacker.
6.  The attacker may use the SQL injection to bypass authentication, allowing them to access administrative functions.
7.  The attacker may use the SQL injection to modify inventory data, manipulate sales records, or create fraudulent transactions.
8.  The attacker may use the SQL injection to exfiltrate sensitive data such as customer information, financial records, and administrator credentials.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to unauthorized access to sensitive data, modification of inventory and sales records, and potentially full control of the application and underlying server. This could result in financial loss, reputational damage, and legal repercussions for affected organizations. Given the public availability of the exploit, the risk of widespread exploitation is high. The impact could include data breaches, financial fraud, and complete system compromise.

## Recommendation

*   Deploy the Sigma rule `Detecting SQL Injection Attempts via URI` to identify malicious requests targeting the vulnerable endpoint.
*   Apply input validation and sanitization to the `ID` parameter in the `/ajax.php?action=save_receiving` file to prevent SQL injection attacks.
*   Monitor web server logs for suspicious activity, such as error messages or unusual requests targeting the `/ajax.php?action=save_receiving` endpoint (webserver log source).
*   Upgrade to a patched version of the application or implement a web application firewall (WAF) rule to block malicious requests.
*   Implement least privilege principles for database access to limit the impact of successful SQL injection attacks.
