---
title: YesWiki Second-Order SQL Injection via Unescaped Page Tag in API Controller
slug: 2026-07-yeswiki-second-order-sqli
description: A critical second-order SQL injection vulnerability (GHSA-8f2v-2qhj-gfwg) in YesWiki versions up to 4.6.5 allows a low-privilege authenticated attacker to execute arbitrary SQL commands via an unescaped page tag in the `ApiController::deletePage()` API, leading to time-based blind data exfiltration.
date: "2026-07-09T21:09:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
  - yeswiki
  - ghsa
vendors:
  - YesWiki
products:
  - YesWiki 4.6.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a low-privilege authenticated user can therefore create a page whose tag is a SQL fragment... and then invoke the delete endpoint to execute arbitrary SQL inside the wiki database
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 'This is a classic second-order SQL injection: the `INSERT` correctly escapes the value... the input passes every ''is this value safe to put in the database?'' check; the sink is the *read-back-and-reuse* path, where escaping is omitted.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'Blind extraction of any column the wiki database account can read: user password hashes... email addresses... private page bodies'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: time-based blind data exfiltration from any table.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8f2v-2qhj-gfwg
rules:
  - title: Detect YesWiki SQLi Attempt via URL-encoded Single Quote
    description: Detects attempts to exploit GHSA-8f2v-2qhj-gfwg, a second-order SQL injection in YesWiki, by identifying API requests with a URL-encoded single quote (%27) in the page tag parameter.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
---

A critical second-order SQL injection vulnerability (GHSA-8f2v-2qhj-gfwg) has been identified in YesWiki versions up to and including 4.6.5, affecting its `ApiController::deletePage()` API endpoint. This flaw allows a low-privilege authenticated attacker to execute arbitrary SQL commands within the wiki's database, leading to potential data exfiltration. The vulnerability occurs because the application, while correctly escaping SQL metacharacters upon initial insertion of a page tag (e.g., `SleepTag' OR SLEEP(2)-- `) into the `yeswiki_pages` table, fails to re-escape this stored, attacker-controlled tag when it's later retrieved and used in a `DELETE FROM ..._links WHERE to_tag = '$tag'` query. This second-order behavior bypasses typical input validation and enables time-based blind data exfiltration of sensitive information like user credentials, private page content, and other database records. The issue is exposed via the `DELETE /api/pages/{tag}` route, which is accessible to any authenticated user.

## Attack Chain

1. **Initial Compromise**: A low-privilege authenticated user gains access to a YesWiki instance.
2. **Malicious Page Creation**: The attacker sends a `POST` request to `/api/pages/{tag}` with a URL-encoded malicious tag (e.g., `SleepTag%27%20OR%20SLEEP(2)--%20`) containing SQL metacharacters. This tag is stored unescaped in the `yeswiki_pages` database table.
3. **Linker Page Creation**: The attacker creates a second, benign page, for example, `LinkPoc`, via `POST /api/pages/LinkPoc`.
4. **Establish Link**: The attacker updates the `LinkPoc` page (e.g., via the `LinkPoc/edit` web editor handler) to include a reference to the malicious page using `{{include page="<evil tag>"}}`. This action causes the application to insert a row into the `yeswiki_links` table, establishing a link to the malicious page and storing its raw, unescaped tag as `to_tag`.
5. **Vulnerability Trigger**: The attacker sends a `DELETE` request to `/api/pages/{evil-tag}` for the malicious page. The `DELETE` request targets the same URL-encoded malicious tag as created in step 2.
6. **SQL Injection Execution**: During the deletion process, the YesWiki application retrieves the stored malicious tag from the database and uses it unescaped in an SQL query like `DELETE FROM yeswiki_links WHERE to_tag = '$tag'`. The injected SQL (e.g., `OR SLEEP(2)-- `) is then executed within the database.
7. **Data Exfiltration**: By varying the injected SQL payload, such as using conditional `SLEEP()` statements, the attacker can perform time-based blind data exfiltration of sensitive information from any accessible database table.

## Impact

Successful exploitation of this vulnerability can lead to time-based blind exfiltration of sensitive data from the YesWiki database. This includes highly sensitive information such as user password hashes (`_users.password`), email addresses, Access Control List (ACL) configurations (`_acls.list`), private page bodies (`_pages.body`), and database session data. Given the "acl:+" access control, any authenticated user, regardless of their privilege level, can initiate this attack. The impact can range from unauthorized disclosure of user data to full compromise of the wiki's content and user base.

## Recommendation

1. Immediately patch YesWiki installations to the latest version to address GHSA-8f2v-2qhj-gfwg.
2. Deploy the `Detect YesWiki SQLi Attempt via URL-encoded Single Quote` Sigma rule to your SIEM and tune it for your environment.
3. Enable comprehensive webserver logging (e.g., access logs) for the `webserver` category to activate the provided Sigma rule.
