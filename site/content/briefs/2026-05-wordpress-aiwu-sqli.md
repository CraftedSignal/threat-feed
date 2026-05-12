---
title: AIWU WordPress Plugin Vulnerable to SQL Injection (CVE-2026-2993)
slug: 2026-05-wordpress-aiwu-sqli
description: The AI Chatbot & Workflow Automation by AIWU plugin for WordPress is vulnerable to SQL Injection (CVE-2026-2993) in versions up to 1.4.17, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-12T09:17:24Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - sqli
  - wordpress
  - injection
vendors:
  - AIWU
products:
  - AI Chatbot & Workflow Automation by AIWU plugin for WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-2993
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2993
rules:
  - title: Detect CVE-2026-2993 Exploitation — AIWU WordPress Plugin SQL Injection
    description: Detects CVE-2026-2993 exploitation — SQL injection attempts against the AIWU WordPress plugin by detecting common SQL injection payloads in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious WordPress Plugin Access
    description: Detects access to common WordPress plugin directories, which may indicate reconnaissance or exploitation activity.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
rules_count: 2
---

The AI Chatbot & Workflow Automation by AIWU plugin for WordPress, versions up to and including 1.4.17, contains a SQL Injection vulnerability (CVE-2026-2993). This flaw stems from insufficient input sanitization of user-supplied parameters and inadequate preparation of the SQL query within the `getListForTbl()` function. Successful exploitation enables unauthenticated attackers to inject malicious SQL queries, potentially extracting sensitive information from the WordPress database. While version 1.4.11 introduced a partial mitigation involving a nonce check, this only affects administrative access and does not fully resolve the vulnerability. This vulnerability allows for database exfiltration and potential compromise of the WordPress site.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable AI Chatbot & Workflow Automation by AIWU plugin (version <= 1.4.17).
2. The attacker crafts a malicious HTTP request targeting an endpoint that uses the `getListForTbl()` function.
3. The attacker injects SQL code into a user-supplied parameter within the HTTP request, exploiting the lack of proper sanitization.
4. The injected SQL code is appended to the existing SQL query executed by the `getListForTbl()` function.
5. The modified SQL query executes against the WordPress database.
6. The attacker leverages the SQL injection to extract sensitive data such as user credentials, API keys, or other confidential information.
7. The extracted data is returned to the attacker via the HTTP response.
8. The attacker may further compromise the WordPress site or connected systems using the exfiltrated data.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-2993) in the AIWU WordPress plugin can lead to the unauthorized disclosure of sensitive information stored in the WordPress database. This may include user credentials, customer data, API keys, and other confidential information. Depending on the extracted data, attackers could further compromise the WordPress site, escalate privileges, or gain access to connected systems. This poses a significant risk to the confidentiality, integrity, and availability of the affected WordPress site and its data.

## Recommendation

*   Apply available patches to upgrade the AI Chatbot & Workflow Automation by AIWU plugin for WordPress to a version greater than 1.4.17 to remediate CVE-2026-2993.
*   Deploy the Sigma rule "Detect CVE-2026-2993 Exploitation — AIWU WordPress Plugin SQL Injection" to your SIEM to detect exploitation attempts targeting the vulnerable plugin.
*   Implement web application firewall (WAF) rules to block requests containing suspicious SQL injection patterns targeting WordPress plugins.
*   Review and audit WordPress plugin code for proper input sanitization and parameterized queries to prevent SQL injection vulnerabilities.
