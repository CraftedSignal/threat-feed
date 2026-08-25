---
title: SQL Injection Vulnerability in Total Donations WordPress Plugin
slug: 2026-08-total-donations-sqli
description: The Total Donations plugin for WordPress versions up to 2.0.5 is vulnerable to unauthenticated SQL injection, allowing attackers to extract sensitive database information.
date: "2026-08-25T10:07:20Z"
lastmod: "2026-08-25T16:17:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-78568&utm_source=rss&utm_medium=rss
vendors:
  - KlbTheme
products:
  - Total Donations
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Total Donations plugin for WordPress is vulnerable to SQL Injection in all versions up to, and including, 2.0.5.
    confidence_band: high
cves:
  - id: CVE-2026-78568
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78568
  - https://patchstack.com/database/wordpress/plugin/totaldonations/vulnerability/wordpress-total-donations-plugin-2-0-5-sql-injection-vulnerability
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/0c3ecf70-544f-49c1-a943-86df89685b58
  - https://sploitus.com/exploit?id=CVE-2026-78568&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-78568 Exploitation - SQL Injection in Total Donations Plugin
    description: Detects potential SQL injection attempts targeting the Total Donations WordPress plugin by identifying common SQL control characters in parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Total Donations plugin to version > 2.0.5
      owner: IT Operations
      due: 24h
      evidence: Plugin version 2.0.5 and below are affected.
  mitigation_plan:
    - priority: immediate
      action: WAF/IPS blocking of SQLi patterns targeting plugin paths
      owner: SOC
      addresses: CVE-2026-78568
      evidence: NVD/Wordfence advisory
updates:
  - at: "2026-08-25T16:17:55Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-78568&utm_source=rss&utm_medium=rss
---

The Total Donations plugin for WordPress (up to and including version 2.0.5) contains a critical SQL injection vulnerability identified as CVE-2026-78568. The flaw exists due to insufficient input validation and a lack of parameterized queries when handling user-supplied parameters. This security deficiency allows unauthenticated remote attackers to append arbitrary SQL commands to existing database queries. Successful exploitation permits an attacker to perform unauthorized operations on the backend database, such as exfiltrating sensitive data, modifying application content, or disrupting service availability. Given the plugin's function, it is likely to be targeted for the extraction of donor or administrative information.

## Attack Chain

1. The attacker identifies a target WordPress site utilizing the Total Donations plugin version 2.0.5 or earlier.
2. The attacker crafts an HTTP GET or POST request containing a malicious SQL payload targeted at an exposed parameter within the plugin's input fields.
3. The request is transmitted to the web server hosting the vulnerable WordPress instance.
4. The web application's input processing logic fails to properly sanitize or escape the attacker-supplied parameter.
5. The plugin concatenates the malicious input directly into a database query string.
6. The database engine executes the concatenated query, allowing the injected SQL commands to run with the privileges of the database user.
7. The attacker iterates through database tables to exfiltrate sensitive data via boolean-based or union-based injection techniques.

## Impact

Successful exploitation of CVE-2026-78568 can lead to the complete compromise of the site's database. This includes the potential theft of sensitive user data, donor information, and site configuration details. Given the critical CVSS score of 9.8, exploitation is unauthenticated and requires no user interaction, making it highly attractive for automated botnets scanning the web for vulnerable WordPress plugins.

## Recommendation

* Update the Total Donations plugin to the latest available version beyond 2.0.5 immediately to remediate CVE-2026-78568.
* If an update is not immediately available, disable the plugin or restrict access to the affected web paths at the WAF level.
* Monitor web server logs for HTTP requests containing common SQL injection characters (such as single quotes, semicolons, and comment indicators) targeting plugin-specific paths.
* Deploy the provided Sigma rule to detect anomalous SQL injection patterns in web server logs.
