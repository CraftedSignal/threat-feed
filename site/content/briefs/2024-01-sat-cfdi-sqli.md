---
title: SAT CFDI 3.3 SQL Injection Vulnerability (CVE-2018-25202)
slug: 2024-01-sat-cfdi-sqli
description: SAT CFDI 3.3 is vulnerable to SQL injection via the 'id' parameter in the signIn endpoint, allowing attackers to manipulate database queries, potentially leading to sensitive data extraction or application compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2018-25202
  - sql-injection
  - web-application
vendors:
  - SAT
products:
  - CFDI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25202
  - https://www.exploit-db.com/exploits/44726
  - https://www.vulncheck.com/advisories/sat-cfdi-sql-injection-via-signin-endpoint
rules:
  - title: Detect Suspicious SAT CFDI SignIn SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the SAT CFDI signIn endpoint via POST requests with suspicious 'id' parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Boolean-Based Blind SQL Injection
    description: Detects boolean-based blind SQL injection attempts based on extended response times.
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

SAT CFDI 3.3, a system used for digital tax receipts, contains a critical SQL injection vulnerability (CVE-2018-25202) in its signIn endpoint. The vulnerability allows unauthenticated attackers to inject arbitrary SQL code by manipulating the 'id' parameter within POST requests. Successful exploitation can lead to the extraction of sensitive information from the database or complete compromise of the vulnerable application. This vulnerability was disclosed in March 2026 and poses a significant risk to organizations using affected versions of SAT CFDI. Due to the sensitive nature of the data handled by CFDI systems, organizations should prioritize patching or mitigating this vulnerability.

## Attack Chain

1. An attacker identifies a vulnerable SAT CFDI 3.3 instance.
2. The attacker crafts a malicious POST request targeting the `/signIn` endpoint.
3. The attacker injects SQL code into the `id` parameter of the POST request. This is achieved by exploiting the lack of proper sanitization of the 'id' parameter.
4. The server executes the injected SQL code against the application's database. The attacker leverages boolean-based blind, stacked queries, or time-based blind SQL injection techniques to bypass security measures.
5. Through successful SQL injection, the attacker extracts sensitive data, such as user credentials, financial records, or other confidential information stored in the database.
6. Alternatively, the attacker may use SQL injection to modify data within the database, potentially leading to fraudulent transactions or data corruption.
7. The attacker could potentially leverage database access to gain shell access to the underlying server, leading to a complete system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability could result in the extraction of sensitive data, including financial records and user credentials. This can lead to financial loss, identity theft, and reputational damage. In more severe cases, attackers could gain control of the entire application and its underlying server. The number of potential victims is dependent on the number of organizations utilizing the vulnerable SAT CFDI 3.3 software.

## Recommendation

*   Apply any available patches or updates for SAT CFDI 3.3 to address CVE-2018-25202 immediately.
*   Implement input validation and sanitization for all user-supplied data, especially within the `signIn` endpoint, to prevent SQL injection attacks.
*   Deploy the Sigma rule "Detect Suspicious SAT CFDI SignIn SQL Injection Attempts" to your SIEM to monitor for exploitation attempts against the `/signIn` endpoint.
*   Regularly review and update web application firewall (WAF) rules to block known SQL injection payloads and patterns.
