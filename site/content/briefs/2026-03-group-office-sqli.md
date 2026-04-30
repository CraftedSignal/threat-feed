---
title: Group-Office JMAP Contact/Query SQL Injection Vulnerability
slug: 2026-03-group-office-sqli
description: An authenticated SQL Injection vulnerability in Group-Office's JMAP Contact/query endpoint allows data extraction, including session tokens, leading to account takeover if unpatched.
date: "2026-03-27T15:16:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - cve-2026-33755
  - group-office
  - jmap
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33755
rules:
  - title: Group-Office Suspicious JMAP Contact Query
    description: Detects suspicious POST requests to the /jmap endpoint that may indicate SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Group-Office Potential Session Token Theft
    description: Detects potential session token theft based on unusual user agent or source IP changes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Group-Office, an enterprise CRM and groupware tool, contains a critical SQL injection vulnerability affecting versions prior to 6.8.158, 25.0.92, and 26.0.17. The vulnerability resides in the JMAP `Contact/query` endpoint. Any authenticated user with basic address book access can exploit this flaw to extract arbitrary data from the database. A successful exploit allows an attacker to retrieve sensitive information such as active session tokens belonging to other users. This can lead to complete account takeover, including the System Administrator account, without requiring the user's password. Applying the security patches released in versions 6.8.158, 25.0.92, and 26.0.17 resolves this vulnerability.

## Attack Chain

1. An attacker authenticates to the Group-Office application with a valid user account that has basic address book access privileges.
2. The attacker crafts a malicious JMAP `Contact/query` request containing a SQL injection payload within a parameter processed by the vulnerable endpoint.
3. The Group-Office application processes the crafted request without proper sanitization, allowing the SQL injection payload to be executed against the database.
4. The SQL injection attack is successful, allowing the attacker to extract sensitive information, including session tokens, user credentials, or other privileged data, from the database.
5. The attacker parses the database response and identifies valid session tokens belonging to other users.
6. The attacker uses the stolen session token to hijack another user's session, bypassing normal authentication procedures.
7. The attacker accesses the target user's account, gaining unauthorized access to sensitive data and functionalities.
8. Depending on the compromised user's privileges, the attacker can escalate privileges, access sensitive data, or perform administrative actions, leading to a complete system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to take over any account within the Group-Office system. The impact includes unauthorized access to sensitive customer data, financial records, and internal communications. System administrators are particularly at risk, as their compromise grants attackers full control over the Group-Office environment. This could lead to data breaches, service disruption, and reputational damage. The CVSS v3.1 base score is rated 8.8, highlighting the high severity of this vulnerability.

## Recommendation

*   Upgrade Group-Office instances to version 6.8.158, 25.0.92, or 26.0.17 to patch CVE-2026-33755.
*   Inspect web server logs for suspicious POST requests to the `/jmap` endpoint containing potentially malicious SQL syntax, as indicated in the rule "Group-Office Suspicious JMAP Contact Query".
*   Deploy the Sigma rule "Group-Office Potential Session Token Theft" to detect unauthorized access attempts using potentially stolen session tokens.
*   Implement robust input validation and sanitization measures to prevent SQL injection vulnerabilities in all web applications.
