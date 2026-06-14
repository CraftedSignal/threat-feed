---
title: Pimcore Platform SQL Injection in DataObject Composite Index Handling
slug: 2026-05-pimcore-sqli
description: A SQL injection vulnerability exists in Pimcore Platform when handling DataObject composite indices during class definition import/save, allowing an authenticated administrative user to inject attacker-controlled composite index metadata, leading to unintended SQL execution in the backend, specifically via the `index_columns` element.
date: "2026-05-28T20:47:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - pimcore
vendors:
  - Pimcore
products:
  - pimcore/pimcore (<= 12.3.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5394
    epss: 0.00011
references:
  - https://github.com/advisories/GHSA-r2f4-ff2p-xc64
  - https://fluidattacks.com/advisories/dragons
rules:
  - title: Detect Pimcore SQL Injection via Composite Index Manipulation
    description: Detects CVE-2026-5394 exploitation - Attempts to inject SQL commands into the `index_columns` field during class definition import/save in Pimcore.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Pimcore Class Definition Import with Suspicious Composite Indices
    description: Detects suspicious characters or commands within the Composite Indices parameters when importing or saving class definitions in Pimcore, potentially indicating SQL injection attempts.
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

Pimcore Platform is vulnerable to SQL injection in the handling of DataObject composite indices during class definition import and save. An authenticated administrative user with the ability to import or save DataObject class definitions can inject attacker-controlled composite index metadata, leading to unintended SQL execution in the backend. The vulnerability lies in the lack of proper validation of the `index_columns` element within `compositeIndices`, which is directly concatenated into `ALTER TABLE` statements. This allows for the injection of arbitrary SQL, potentially leading to unauthorized schema modification, denial of service, and data integrity compromise. The issue affects Pimcore versions up to and including 12.3.6, with the vulnerability residing in the `compositeIndices` handling during class definition import/save operations.

## Attack Chain

1. An attacker authenticates as an administrative user with privileges to manage DataObject class definitions.
2. The attacker crafts a malicious JSON payload containing a `compositeIndices` section.
3. Within the `compositeIndices` section, the attacker injects SQL code into the `index_columns` field. For example: `"slider), DROP COLUMN \`oo_className\` -- "`
4. The attacker imports the crafted JSON payload via the `/pimcore-studio/api/class/definition/configuration-view/detail/1/import` endpoint or saves the class definition through the administrative workflow.
5. `importClassDefinitionFromJson()` decodes the attacker-controlled JSON and forwards `compositeIndices` to `setCompositeIndices()`.
6. `setCompositeIndices()` stores the values without sanitizing identifier content.
7. `ClassDefinition::save()` reaches `ClassDefinition\Dao::update()` which then calls `updateCompositeIndices()` on tables like `object_store_<classId>` and `object_query_<classId>`.
8. The injected SQL code is concatenated into an `ALTER TABLE` statement, which is then executed against the Pimcore database via Doctrine DBAL, leading to unintended schema modifications.

## Impact

The SQL injection vulnerability allows a privileged attacker to alter backend SQL behavior during class-definition import/save, resulting in schema modification on Pimcore object tables. This can lead to unauthorized schema changes, backend denial of service by breaking expected table layouts, and data integrity issues for DataObject storage and queries. Versions up to and including v12.3.6 are vulnerable.

## Recommendation

*   Deploy the Sigma rule "Detect Pimcore SQL Injection via Composite Index Manipulation" to your SIEM and tune for your environment to detect exploitation attempts (rules).
*   Apply input validation and sanitization to the `index_columns` field in `Pimcore\Model\DataObject\ClassDefinition::setCompositeIndices()` to prevent SQL injection (code).
*   Upgrade Pimcore to a patched version that addresses CVE-2026-5394 when available.
*   Monitor web server logs for POST requests to `/pimcore-studio/api/class/definition/configuration-view/detail/*/import` with suspicious characters in the `compositeIndices` parameter (logs).
