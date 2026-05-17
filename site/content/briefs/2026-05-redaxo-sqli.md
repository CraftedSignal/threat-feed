---
title: Redaxo CMS MyEvents Addon SQL Injection Vulnerability (CVE-2018-25319)
slug: 2026-05-redaxo-sqli
description: Redaxo CMS Addon MyEvents version 2.2.1 contains an SQL injection vulnerability (CVE-2018-25319) that allows authenticated attackers to manipulate database queries by injecting SQL code through the myevents_id parameter, enabling the extraction or modification of sensitive database information.
date: "2026-05-17T13:18:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - cve-2018-25319
  - redaxo
vendors:
  - Redaxo
products:
  - MyEvents Addon 2.2.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25319
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25319
  - http://www.github.com/wende60/myevents
  - https://www.exploit-db.com/exploits/44261
  - https://www.vulncheck.com/advisories/redaxo-cms-addon-myevents-sql-injection-via-event-add-php
rules:
  - title: Detect CVE-2018-25319 Exploitation — Redaxo MyEvents SQL Injection
    description: Detects CVE-2018-25319 exploitation — SQL injection attempts in Redaxo MyEvents Addon via crafted GET requests to event_add.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Redaxo MyEvents Addon SQL Injection - Error Responses
    description: Detects potential SQL injection attempts in Redaxo MyEvents Addon based on error responses.
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

Redaxo CMS is vulnerable to SQL injection in the MyEvents Addon version 2.2.1. CVE-2018-25319 allows authenticated attackers to inject arbitrary SQL commands via the `myevents_id` parameter. Successful exploitation allows attackers to manipulate database queries, potentially leading to information disclosure or data modification. This vulnerability requires the attacker to be authenticated, limiting the scope of potential attackers. However, exploitation is relatively straightforward, involving crafted GET requests.

## Attack Chain

1. The attacker authenticates to the Redaxo CMS instance.
2. The attacker crafts a malicious GET request targeting the `/redaxo/index.php?addon=myevents&page=event_add` endpoint.
3. The crafted GET request includes a `myevents_id` parameter containing SQL injection payload. For example, `myevents_id=1' AND 1=1;--`.
4. The web application processes the request and executes the injected SQL code against the database.
5. The injected SQL query allows the attacker to extract sensitive information such as usernames, passwords, or other database content.
6. The attacker analyzes the retrieved data to identify further attack vectors or sensitive information.
7. The attacker modifies database records to escalate privileges or deface the website.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25319) can lead to unauthorized access to sensitive data, including user credentials and confidential information stored in the Redaxo CMS database. Attackers could potentially escalate their privileges, modify website content, or compromise the entire system. The severity is rated as High with a CVSS score of 7.1.

## Recommendation

*   Apply any available patches or updates for the Redaxo CMS MyEvents Addon to remediate CVE-2018-25319.
*   Deploy the Sigma rule `Detect CVE-2018-25319 Exploitation — Redaxo MyEvents SQL Injection` to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious GET requests to `/redaxo/index.php?addon=myevents&page=event_add` with unusual characters in the `myevents_id` parameter (see IOCs).
*   Implement input validation and sanitization for all user-supplied data, especially for parameters used in database queries.
*   Enforce least privilege principles to limit the impact of potential SQL injection attacks.
