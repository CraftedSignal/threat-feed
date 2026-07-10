---
title: 'CVE-2026-15290: Ultimate Member Plugin Blind SQL Injection'
slug: 2026-07-ultimate-member-sqli
description: The Ultimate Member plugin for WordPress is vulnerable to blind SQL Injection via the 'search' parameter in all versions up to and including 2.10.1, due to insufficient escaping of user-supplied input and inadequate preparation of existing SQL queries, allowing unauthenticated attackers to append additional SQL queries and extract sensitive information from the database.
date: "2026-07-10T05:20:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ultimatemember:ultimate_member:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - sql-injection
  - web-vulnerability
vendors:
  - Ultimate Member
  - WordPress
products:
  - Ultimate Member - User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin <= 2.10.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Ultimate Member – User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to blind SQL Injection via the search parameter... makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: '...that can be used to extract sensitive information from the database.'
    confidence_band: high
cves:
  - id: CVE-2026-15290
    cvss: 7.5
  - id: CVE-2025-0308
    cvss: 7.5
    epss: 0.00513
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15290
rules:
  - title: Detect Blind SQL Injection Attempts in Ultimate Member Plugin (CVE-2026-15290)
    description: Detects CVE-2026-15290 exploitation attempts - blind SQL Injection patterns in the 'search' parameter of the Ultimate Member plugin, which could lead to sensitive data extraction.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-15290 details a critical blind SQL Injection vulnerability affecting the Ultimate Member - User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin for WordPress, impacting all versions up to and including 2.10.1. The vulnerability originates from insufficient escaping of user-supplied input in the `search` parameter and inadequate preparation of existing SQL queries. This flaw enables unauthenticated attackers to append malicious SQL queries to legitimate ones, facilitating the extraction of sensitive information from the underlying database. A partial patch for this specific issue was introduced in version 2.9.2, which initially aimed to address CVE-2025-0308. Successful exploitation poses a significant risk of data breaches and unauthorized access to a WordPress site's sensitive data.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP GET or POST request targeting a WordPress site running the Ultimate Member plugin.
2. The crafted request includes SQL injection payloads within the `search` parameter (e.g., `?search=test%27%20AND%20SLEEP(5)--%20` or `?search=admin%27%20OR%201=1--%20`).
3. Due to inadequate input sanitization and lack of parameterized queries within the plugin's code, the malicious input from the `search` parameter is directly incorporated into a backend SQL query.
4. The injected blind SQL query executes on the database server, causing a differential response, such as a time delay for time-based attacks or a distinct content change for boolean-based attacks.
5. The attacker analyzes the web server's response (e.g., HTTP response time, page content) to infer the result of the injected SQL condition.
6. The attacker iteratively sends numerous such requests, modifying the payload in the `search` parameter to extract sensitive data, character by character, or by evaluating true/false conditions.
7. Sensitive information, such as user credentials, API keys, or private configuration data, is systematically exfiltrated from the WordPress database.

## Impact

The successful exploitation of CVE-2026-15290 allows unauthenticated attackers to extract sensitive data from the WordPress database. This could lead to a compromise of user accounts, administrative credentials, and other confidential information stored within the system. The stolen data could then be used for further attacks, identity theft, or sold on illicit markets, leading to severe financial, reputational, and operational damage for affected organizations. The vulnerability's high CVSS v3.1 score of 7.5 reflects the significant risk posed by unauthorized data disclosure without any prior authentication required.

## Recommendation

* Immediately update the Ultimate Member plugin for WordPress to a version patched against CVE-2026-15290 (versions higher than 2.10.1).
* Deploy the Sigma rule `Detect Blind SQL Injection Attempts in Ultimate Member Plugin` to your SIEM to identify and alert on potential exploitation attempts via the `search` parameter.
* Ensure detailed web server access logs are enabled and collected for your WordPress instances, specifically capturing full HTTP request URLs and query parameters.
