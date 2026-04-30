---
title: YesWiki Authenticated SQL Injection Vulnerability
slug: 2024-01-24-yeswiki-sqli
description: YesWiki is vulnerable to authenticated SQL Injection via the id_fiche parameter in the EntryManager::formatDataBeforeSave() function, allowing attackers to inject arbitrary SQL commands and potentially extract sensitive data.
date: "2026-04-18T01:00:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - yeswiki
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-f58v-p6j9-24c2
iocs:
  - type: url
    value: http://TARGET/?api/entries/1
  - type: domain
    value: githubusercontent.com
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: Detect YesWiki SQL Injection Attempt via API Entries
    description: Detects attempts to exploit the YesWiki SQL injection vulnerability in the /api/entries endpoint by looking for suspicious SQL syntax in the id_fiche parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect YesWiki Error Based SQL Injection
    description: Detects YesWiki SQL injection attempts based on MySQL error messages in the webserver logs caused by the extractvalue function.
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

YesWiki versions 4.6.0 and earlier are vulnerable to SQL injection in the bazar module. This vulnerability exists in `tools/bazar/services/EntryManager.php` within the `formatDataBeforeSave()` function. The `$data['id_fiche']` value, derived from the `$_POST['id_fiche']` parameter, is directly concatenated into a raw SQL query without proper sanitization. An authenticated attacker can exploit this by sending a crafted POST request to the `/api/entries/{formId}` endpoint. Successful exploitation enables time-based blind SQL injection, potentially leading to complete database compromise. The vulnerability was confirmed using a Docker PoC demonstrating the ability to induce a time delay using the SLEEP() function within the injected SQL.

## Attack Chain

1. Attacker authenticates to the YesWiki application as any user. This requires a valid `wikini_session` cookie.
2. Attacker crafts a POST request to `/api/entries/{formId}`, where `{formId}` is the ID of an existing bazar form.
3. The POST request includes the `id_fiche` parameter with a malicious SQL payload, such as `' OR SLEEP(3) OR '`.
4. `ApiController::createEntry()` processes the request and calls `isEntry($_POST['id_fiche'])`.
5. Since the injected SQL will likely not correspond to an existing entry, the `create()` method is invoked.
6. The `create()` method calls `formatDataBeforeSave()`, which contains the SQL injection vulnerability at line 704 in `EntryManager.php`.
7. The injected SQL payload is executed by the database server via `dbService->loadSingle()`, without proper escaping or parameterization.
8. If successful, the attacker can extract sensitive information from the database, such as usernames, passwords, and other confidential data. They can also modify data within the database.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the complete compromise of the YesWiki database. This includes the potential to access and exfiltrate sensitive data, such as user credentials, configuration details, and business-critical information. Attackers can also modify or delete data, leading to data integrity issues and service disruption. Since any authenticated user can trigger the vulnerability, the impact is widespread. The vulnerability affects composer/yeswiki/yeswiki versions 4.6.0 and earlier.

## Recommendation

*   Apply the provided patch in `tools/bazar/services/EntryManager.php` by escaping the `$data['id_fiche']` value before using it in the SQL query (see Proposed Fix in Content section).
*   Deploy the Sigma rule "Detect YesWiki SQL Injection Attempt via API Entries" to detect attempts to exploit this vulnerability via suspicious `id_fiche` POST data.
*   Monitor web server logs for POST requests to `/api/entries/*` with unusually long or complex `id_fiche` parameters, as this could indicate a SQL injection attempt.
*   Review and audit all database queries within the YesWiki application to identify and remediate any other potential SQL injection vulnerabilities.
