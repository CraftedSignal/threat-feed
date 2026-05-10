---
title: Opencart TMD Vendor System Blind SQL Injection Vulnerability (CVE-2021-47928)
slug: 2026-05-opencart-sqli
description: Opencart TMD Vendor System 3.x contains a blind SQL injection vulnerability (CVE-2021-47928) that allows unauthenticated attackers to extract database information by injecting SQL code through the product_id parameter, potentially leading to account takeover and data exfiltration.
date: "2026-05-10T13:19:42Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve-2021-47928
  - opencart
  - web-application
vendors:
  - Opencart
products:
  - TMD Vendor System 3.x
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2021-47928
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47928
  - https://www.exploit-db.com/exploits/50493
  - https://www.opencartextensions.in/
  - https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace
  - https://www.vulncheck.com/advisories/opencart-tmd-vendor-system-3-x-blind-sql-injection-via-product-route
rules:
  - title: Detect CVE-2021-47928 Exploitation — Opencart TMD Vendor System Blind SQL Injection
    description: Detects CVE-2021-47928 exploitation — attempts to exploit a blind SQL injection vulnerability in Opencart TMD Vendor System 3.x via the product_id parameter with common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1213
    data_sources:
      - webserver
  - title: Detect CVE-2021-47928 Exploitation — Opencart TMD Vendor System SQL Error Responses
    description: Detects CVE-2021-47928 exploitation — identifies SQL errors returned by the server in response to a crafted request to the vulnerable Opencart TMD Vendor System 3.x endpoint. Success of the exploit relies on the application returning errors in response to the injected SQL code.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1213
    data_sources:
      - webserver
rules_count: 2
---

Opencart TMD Vendor System 3.x is susceptible to a blind SQL injection vulnerability (CVE-2021-47928) that enables unauthenticated attackers to extract sensitive database information. The vulnerability stems from insufficient input sanitization of the `product_id` parameter, allowing injection of malicious SQL code. By leveraging time-based or content-based blind injection techniques, attackers can enumerate usernames, emails, and password reset codes from the `oc_user` table. This can lead to unauthorized access to user accounts and potential data breaches. This vulnerability was reported to NVD on May 10, 2026.

## Attack Chain

1.  An unauthenticated attacker identifies the vulnerable `product_id` parameter in the Opencart TMD Vendor System 3.x application.
2.  The attacker crafts a malicious HTTP GET request with a SQL injection payload embedded within the `product_id` parameter.
3.  The application processes the crafted request without proper sanitization, passing the malicious SQL code to the database server.
4.  The database server executes the injected SQL code, performing actions such as querying the `oc_user` table.
5.  Using blind SQL injection techniques (time-based or content-based), the attacker infers information about the database structure and contents.
6.  The attacker iterates through the database, extracting sensitive information such as usernames, emails, and password reset codes.
7.  The attacker uses the extracted credentials or password reset codes to gain unauthorized access to user accounts.
8.  The attacker may further compromise the system, exfiltrate data, or perform other malicious activities.

## Impact

Successful exploitation of this vulnerability (CVE-2021-47928) can lead to complete database compromise, including exposure of user credentials, personally identifiable information (PII), and other sensitive data. Unauthenticated attackers can leverage this access to take over administrator accounts, modify website content, or gain deeper access into the target network. Given the potential for widespread exploitation, organizations using Opencart TMD Vendor System 3.x are at significant risk.

## Recommendation

*   Apply available patches or upgrade to a secure version of Opencart TMD Vendor System to remediate CVE-2021-47928.
*   Deploy the Sigma rule "Detect CVE-2021-47928 Exploitation — Opencart TMD Vendor System Blind SQL Injection" to identify exploitation attempts in web server logs.
*   Implement web application firewall (WAF) rules to block requests containing SQL injection payloads targeting the `product_id` parameter.
*   Enforce the principle of least privilege on database accounts to limit the impact of successful SQL injection attacks.
*   Regularly review and audit web application code for SQL injection vulnerabilities using static and dynamic analysis tools.
