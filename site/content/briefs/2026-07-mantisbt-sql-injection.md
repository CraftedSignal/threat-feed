---
title: MantisBT SQL Injection via history_order Configuration Value
slug: 2026-07-mantisbt-sql-injection
description: MantisBT versions 2.28.3 and earlier are vulnerable to a SQL injection within the `history_order` configuration value in `core/history_api.php`, allowing an authenticated administrator to inject malicious SQL via the web UI or REST API, which then executes whenever any user views a bug with history entries, leading to sensitive data extraction and potential Remote Code Execution (RCE) via webshell if the MySQL FILE privilege is enabled.
date: "2026-07-15T16:43:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
  - rce
  - mantisbt
vendors:
  - MantisBT
products:
  - MantisBT <= 2.28.3
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: 'If the MySQL FILE privilege is enabled: full RCE via INTO OUTFILE writing a PHP webshell to the web root'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: The admin plants the payload once; any authenticated user viewing a bug with history triggers the injection
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Sensitive data extraction from the entire bugtracker database including user credentials (cookie_string, password hashes), API tokens
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Sensitive data extraction from the entire bugtracker database including user credentials (cookie_string, password hashes), API tokens, and private issue data
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mw6p-33vw-46cc
  - https://github.com/mantisbt/mantisbt/commit/6ad20bea2e01f33c6e4170775ae4d9dbe2c75325
  - https://mantisbt.org/bugs/view.php?id=37123
rules:
  - title: Detects CVE-2026-47142 Exploitation - MantisBT history_order SQLi via INTO OUTFILE
    description: Detects attempts to exploit CVE-2026-47142 by injecting 'INTO OUTFILE' into the MantisBT history_order configuration via the web UI or REST API, aiming for Remote Code Execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

MantisBT versions 2.28.3 and earlier are affected by a high-severity SQL injection vulnerability, identified as CVE-2026-47142. This flaw exists in `core/history_api.php`, where the `history_order` configuration value is unsafely concatenated into a SQL `ORDER BY` clause without proper sanitization or parameterization. An authenticated administrator can exploit this by injecting malicious SQL when setting the `history_order` value via the web UI (`adm_config_set.php`) or the REST API (`PATCH /api/rest/config`). Once injected, the payload executes whenever any user views a bug that includes history entries. Successful exploitation can lead to sensitive data exfiltration from the bugtracker database, including user credentials and API tokens. If the underlying MySQL server has the `FILE` privilege enabled, this vulnerability can escalate to full Remote Code Execution (RCE) by writing a PHP webshell to the web root.

## Attack Chain

1. An authenticated administrator gains access to the MantisBT web UI or REST API.
2. The administrator navigates to the configuration settings or crafts a malicious REST API request to modify system parameters.
3. The administrator injects malicious SQL payload (e.g., for data exfiltration or `INTO OUTFILE` for webshell creation) into the `history_order` configuration value.
4. The MantisBT application stores this unsanitized malicious SQL string in its database as the `history_order` configuration value.
5. Any authenticated user subsequently views a bug within MantisBT that has history entries.
6. When displaying the bug history, the vulnerable `core/history_api.php` concatenates the stored malicious `history_order` value directly into a SQL `ORDER BY` clause.
7. The database executes the crafted SQL query, leading to actions such as sensitive data extraction (e.g., credentials, API tokens, private issue data) from the bugtracker database.
8. If the MySQL server has the `FILE` privilege, the injected SQL can write a PHP webshell to the web root, achieving Remote Code Execution for the attacker.

## Impact

The successful exploitation of CVE-2026-47142 poses a critical risk to the confidentiality and integrity of MantisBT instances. Attackers can extract highly sensitive information, including all user credentials (e.g., `cookie_string`, password hashes), API tokens, and confidential issue data from the entire bugtracker database. Furthermore, if the underlying MySQL server is configured with the `FILE` privilege, the vulnerability can be leveraged to achieve full Remote Code Execution (RCE) on the server by writing a PHP webshell to the web root, giving attackers persistent access and control over the compromised system. While specific victim counts are not available, all MantisBT instances running versions 2.28.3 or earlier are at risk.

## Recommendation

* Patch MantisBT installations immediately to a version beyond 2.28.3, applying the fixes referenced in the GitHub advisory.
* Deploy the provided Sigma rule to your SIEM to detect attempts at injecting `INTO OUTFILE` via the `history_order` configuration.
* Review web server access logs for requests to `adm_config_set.php` or `PATCH /api/rest/config` containing suspicious SQL keywords, especially `INTO OUTFILE` within parameters.
* Restrict the MySQL `FILE` privilege to mitigate the impact of SQL injection leading to RCE if not strictly necessary for application functionality.
