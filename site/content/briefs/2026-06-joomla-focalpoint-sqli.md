---
title: Joomla! FocalPoint Pro/Free SQL Injection (CVE-2017-20263)
slug: 2026-06-joomla-focalpoint-sqli
description: An unauthenticated SQL injection vulnerability (CVE-2017-20263) in Joomla! Component FocalPoint Pro/Free version 1.2.3 allows attackers to execute arbitrary SQL queries via a crafted 'id' parameter in GET requests, leading to sensitive database information disclosure.
date: "2026-06-19T16:34:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - web-vulnerability
  - joomla
  - data-exfiltration
vendors:
  - Focalpointx
products:
  - FocalPoint Pro/Free (1.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
cves:
  - id: CVE-2017-20263
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20263
  - http://focalpointx.com/
  - http://focalpointx.com/demos/focalpoint-pro
  - https://www.exploit-db.com/exploits/42530
  - https://www.vulncheck.com/advisories/joomla-focalpoint-pro-free-sql-injection-via-location
rules:
  - title: Detects CVE-2017-20263 Exploitation Attempt — Joomla! FocalPoint SQLi
    description: Detects attempts to exploit CVE-2017-20263, an unauthenticated SQL injection vulnerability in Joomla! Component FocalPoint Pro/Free via a crafted 'id' parameter in GET requests.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
      - T1537
    data_sources:
      - webserver
rules_count: 1
---

CVE-2017-20263 details a critical SQL injection vulnerability affecting Joomla! Component FocalPoint Pro/Free version 1.2.3. This vulnerability allows unauthenticated attackers to execute arbitrary SQL queries by manipulating the `id` parameter within specific GET requests. By crafting malicious SQL code into the `id` parameter when requesting `index.php` with `option=com_focalpoint` and `view=location`, attackers can force the application to disclose sensitive database information. The vulnerability, first documented in 2026, presents a significant risk to organizations using the affected Joomla! component, potentially leading to unauthorized data exposure and further compromise if database credentials are leaked.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable Joomla! instance running FocalPoint Pro/Free version 1.2.3.
2.  The attacker crafts a malicious HTTP GET request targeting `index.php` on the vulnerable server.
3.  The request includes specific parameters: `option=com_focalpoint` and `view=location`.
4.  The attacker injects SQL commands (e.g., `id=1 UNION SELECT USER(), DATABASE()`) into the `id` parameter of this GET request.
5.  The vulnerable FocalPoint component processes the request without proper sanitization, leading to the execution of the attacker-supplied SQL queries against the backend database.
6.  The database responds to these queries, returning sensitive information such as user credentials, database schemas, or application data within the web application's output.
7.  The attacker parses the HTTP response to extract the disclosed sensitive database information.

## Impact

Successful exploitation of CVE-2017-20263 grants unauthenticated attackers the ability to extract sensitive information directly from the underlying database of the Joomla! application. This can include confidential user data, hashed passwords, session tokens, and configuration details. Such data exfiltration can lead to severe consequences, including further account compromise, unauthorized access to internal systems, or compliance violations. Organizations in any sector using the vulnerable component are at risk of data breaches and reputational damage if their databases are exposed.

## Recommendation

*   Patch CVE-2017-20263 by upgrading the Joomla! FocalPoint Pro/Free component to a version beyond 1.2.3 immediately.
*   Deploy the Sigma rule "Detects CVE-2017-20263 Exploitation Attempt" to your SIEM system to identify exploitation attempts.
*   Enable comprehensive web server access logging to capture full HTTP request details, including query strings, which are essential for the detection rule.
