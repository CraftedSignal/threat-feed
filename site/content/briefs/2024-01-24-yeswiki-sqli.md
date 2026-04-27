---
title: YesWiki Authenticated SQL Injection Vulnerability
slug: 2024-01-24-yeswiki-sqli
description: YesWiki is vulnerable to authenticated SQL Injection via the id_fiche parameter in the EntryManager::formatDataBeforeSave() function, allowing attackers to inject arbitrary SQL commands and potentially extract sensitive data.
date: "2026-04-18T01:00:30Z"
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

YesWiki versions 4.6.0 and earlier are vulnerable to SQL injection in the bazar module. This vulnerability exists in `tools/bazar/services/EntryManager.php` within the `formatDataBeforeSave()` function. The `$data['id_fiche']` value, derived from the `$_POST['id_fiche']` parameter, is directly concatenated into a raw SQL query without proper sanitization. An authenticated attacker can exploit this by sending a crafted POST request to the `/api/entries/{formId}` endpoint. Successful exploitation…
