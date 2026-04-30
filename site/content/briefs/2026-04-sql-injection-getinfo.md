---
title: Unauthenticated SQL Injection Vulnerability in getinfo Endpoint (CVE-2026-33614)
slug: 2026-04-sql-injection-getinfo
description: An unauthenticated SQL Injection vulnerability (CVE-2026-33614) in the getinfo endpoint allows a remote attacker to execute arbitrary SQL commands due to improper neutralization of special elements, potentially leading to a total loss of confidentiality.
date: "2026-04-02T10:16:16Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33614
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33614
  - https://certvde.com/de/advisories/VDE-2026-030
  - https://mbconnectline.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2026-030.json
rules:
  - title: Detect Suspicious getinfo SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the getinfo endpoint by looking for common SQL keywords in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages in Web Responses
    description: Detects potential SQL injection exploitation by identifying SQL error messages in the web server response.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33614 describes an unauthenticated SQL Injection vulnerability present in the getinfo endpoint of an unspecified application. Discovered and reported by CERT VDE, the vulnerability stems from the improper neutralization of special elements within a SQL SELECT command. A remote, unauthenticated attacker can exploit this flaw to inject malicious SQL code, potentially gaining unauthorized access to sensitive data. Successful exploitation results in a total loss of confidentiality, as the attacker can retrieve any information stored in the database. The scope of affected products is currently unknown, highlighting the need for further investigation and patching by vendors who utilize similar getinfo endpoints and SQL queries. This vulnerability poses a significant risk as it requires no authentication, making it easily exploitable.

## Attack Chain

1.  Attacker identifies a vulnerable getinfo endpoint that accepts user-supplied input.
2.  Attacker crafts a malicious SQL injection payload, embedding it within a seemingly benign request to the getinfo endpoint.
3.  The application fails to properly sanitize or validate the attacker's input.
4.  The unsanitized input is directly incorporated into a SQL SELECT query executed by the application.
5.  The injected SQL code modifies the original query, potentially bypassing security measures and accessing sensitive data.
6.  The database executes the modified SQL query, treating the injected code as legitimate commands.
7.  The application retrieves the results of the injected query, which may include sensitive data such as usernames, passwords, or financial information.
8.  The attacker receives the leaked data in the response from the getinfo endpoint, completing the data exfiltration.

## Impact

Successful exploitation of CVE-2026-33614 leads to a total loss of confidentiality. Attackers can potentially access and exfiltrate sensitive data stored in the application's database, including user credentials, financial records, and other confidential information. The number of potential victims is unknown, as the affected product is not specified in the CVE. However, any application utilizing a vulnerable getinfo endpoint is at risk. The impact includes data breaches, identity theft, financial fraud, and reputational damage.

## Recommendation

*   Inspect web server logs for suspicious requests to `getinfo` endpoints containing SQL syntax (e.g., `SELECT`, `UNION`, `OR`) to identify potential exploitation attempts. Use the provided Sigma rule `Detect Suspicious getinfo SQL Injection Attempts` for this purpose.
*   Implement input validation and sanitization on all user-supplied input to the `getinfo` endpoint to prevent SQL injection attacks.
*   Deploy parameterized queries or prepared statements to ensure that user input is treated as data, not executable code.
*   Monitor database logs for anomalous SQL queries originating from the application server to detect potential SQL injection activity.
*   Apply the principle of least privilege to database accounts used by the application, limiting their access to only the necessary data.
*   Conduct regular security audits and penetration testing to identify and address potential vulnerabilities, including SQL injection flaws.
