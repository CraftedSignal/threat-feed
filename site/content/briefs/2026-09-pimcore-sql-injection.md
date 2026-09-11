---
title: SQL Injection in Pimcore CustomReportsBundle
slug: 2026-09-pimcore-sql-injection
description: An authenticated SQL injection vulnerability in Pimcore's CustomReportsBundle allows users with specific permissions to execute arbitrary database commands by bypassing a weak keyword blacklist.
date: "2026-09-11T00:55:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pimcore:pimcore:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-application
  - cms
vendors:
  - Pimcore
products:
  - Pimcore (>= 2026.1.0, <= 2026.1.5)
  - Pimcore (>= 12.0.0, <= 12.3.9)
  - Pimcore (< 11.5.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A SQL injection vulnerability exists in the Custom Reports bundle... which are directly concatenated into SQL queries without parameterization.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Exploitation allows reading, modifying, or deleting all data in the database, leading to complete data compromise.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-23rh-xw42-fq82
rules:
  - title: Detect CVE-2026-55416 Exploitation - SQL Injection in Custom Reports
    description: Detects exploitation of CVE-2026-55416 by identifying SQL keywords in POST requests directed at the Custom Reports update endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Pimcore to 2026.1.6, 12.3.10, or 11.5.19
      owner: IT Operations
      due: 24h
      evidence: Source Patches section
    - action: Deploy the provided Sigma rule to detect exploitation attempts
      owner: Detection Engineering
      due: 48h
      evidence: Detection rule provided in brief
  mitigation_plan:
    - priority: immediate
      action: Restrict reports_config permissions to trusted admins
      owner: IT Operations
      addresses: CVE-2026-55416
      evidence: Source Workarounds section
---

Pimcore is susceptible to a high-severity SQL injection vulnerability identified as CVE-2026-55416, affecting the `CustomReportsBundle`. The issue originates in the `Sql.php` adapter, where user-supplied configuration fields - specifically `sql`, `from`, `where`, and `groupby` - are concatenated directly into database queries. While the application implements a regex-based blacklist to filter malicious keywords, the current implementation is insufficient. It fails to block critical SQL injection primitives such as `UNION SELECT`, `INSERT`, subqueries, and MySQL comment injection. 

An attacker with `reports_config` privileges can manipulate these report configuration parameters to gain unauthorized access to the database, including the potential to read, modify, or delete sensitive data. Furthermore, the application fails to cast `$offset` and `$limit` parameters to integers, introducing a secondary injection vector via the LIMIT clause. This vulnerability affects multiple branches of Pimcore, including versions within the 2026.x, 12.x, and 11.x release lines.

## Attack Chain

1. Attacker obtains an authenticated session with `reports_config` permissions.
2. Attacker initiates an HTTP POST request to `/admin/bundle/customreports/custom-report/update`.
3. Attacker embeds malicious SQL payloads within the `configuration` JSON object fields (e.g., `sql`, `where`).
4. The `CustomReportController::updateAction` decodes the input and persists the malicious configuration to the `custom_reports` database table.
5. The application triggers a data retrieval process, calling `Tool\Config::getByName()` to load the configuration.
6. The `Sql::buildQueryString` method concatenates the malicious input strings to form a query, bypassing the incomplete regex filter.
7. The final query is executed via `$db->fetchAllAssociative($sql)`, executing the attacker's arbitrary SQL commands.
8. Attacker retrieves sensitive data or modifies records through the malicious report interface.

## Impact

Successful exploitation results in full database compromise. Attackers can exfiltrate sensitive user data, bypass authentication controls, or alter application state. The vulnerability is accessible to any user granted the `reports_config` permission, which is typically assigned to administrative or reporting roles.

## Recommendation

1. Patch Pimcore immediately by upgrading to versions 2026.1.6, 12.3.10, or 11.5.19 or later.
2. Review and restrict the `reports_config` permission to the smallest necessary set of trusted administrative users.
3. Deploy WAF rules to inspect POST requests to `/admin/bundle/customreports/custom-report/update` for SQL injection patterns, specifically targeting common clauses like `UNION`, `SELECT`, and `INFORMATION_SCHEMA` in the `configuration` parameter.
4. Detection engineers should audit web server logs for suspicious database query patterns originating from the custom reports module.
