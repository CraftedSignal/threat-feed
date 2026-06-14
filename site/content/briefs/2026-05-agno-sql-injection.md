---
title: Agno 2.6.5 ClickHouse Backend SQL Injection (CVE-2026-10105)
slug: 2026-05-agno-sql-injection
description: Agno 2.6.5 is vulnerable to SQL injection in the ClickHouse vector database backend (CVE-2026-10105), enabling attackers to inject arbitrary SQL expressions via malicious metadata in the delete_by_metadata() method, potentially leading to data deletion or information extraction.
date: "2026-05-29T18:18:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-10105
  - database
vendors:
  - ClickHouse
products:
  - agno 2.6.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-10105
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10105
  - https://github.com/agno-agi/agno/issues/7866
  - https://github.com/agno-agi/agno/pull/7883
  - https://github.com/agno-agi/agno/pull/7883/changes/26a7439b803c0ccc9a58ee53572d8088a678923f
  - https://github.com/agno-agi/agno/pull/7883/changes/a0ec99305e782e68ba26f5966c53ad50b5f40132
  - https://www.vulncheck.com/advisories/agno-sql-injection-via-clickhouse-delete-by-metadata
rules:
  - title: Detect CVE-2026-10105 Exploitation Attempt - Malicious Metadata in Agno ClickHouse DELETE Request
    description: Detects CVE-2026-10105 exploitation - identifies requests to the Agno ClickHouse backend containing potentially malicious SQL injection payloads in the metadata keys or values during deletion operations.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Generic SQL Injection Attempts in ClickHouse Logs
    description: Detects generic SQL injection attempts in ClickHouse logs by identifying common SQL injection syntax patterns.
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

Agno 2.6.5, a vector database, is susceptible to a SQL injection vulnerability (CVE-2026-10105) within its ClickHouse backend. This flaw stems from the unsafe use of f-string interpolation in the `clickhousedb.py` module, specifically within the `delete_by_metadata()` method. An attacker can inject arbitrary SQL expressions by supplying crafted metadata keys and values during deletion operations. The vulnerability was reported on May 29, 2026. Successful exploitation can result in unauthorized data manipulation, including deletion of all rows or targeted data removal, as well as information disclosure through error-based or blind SQL injection techniques. This poses a significant risk to data integrity and confidentiality for systems utilizing the affected version of Agno with the ClickHouse backend.

## Attack Chain

1. An attacker identifies an Agno 2.6.5 instance using the ClickHouse vector database backend.
2. The attacker crafts malicious metadata keys and values containing SQL injection payloads, targeting the `delete_by_metadata()` method.
3. The attacker calls the `delete_by_metadata()` method with the crafted metadata.
4. The `clickhousedb.py` module, specifically the `delete_by_metadata()` function, uses an unsafe f-string to interpolate the attacker-supplied metadata directly into a SQL query.
5. The injected SQL code is executed against the ClickHouse database.
6. Depending on the injected SQL, the attacker can delete all rows in a table.
7. The attacker can also target specific rows for deletion by crafting SQL `WHERE` clauses within the injected metadata.
8. The attacker can use error-based or blind SQL injection techniques to extract sensitive information from the database through carefully crafted queries and observing the application's responses.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-10105) can lead to several detrimental outcomes. Attackers could potentially delete all data within the ClickHouse database, causing complete data loss and service disruption. Targeted data deletion can compromise the integrity of specific datasets, leading to inaccurate or incomplete information. Furthermore, sensitive information stored within the database can be extracted through error-based or blind SQL injection, resulting in confidentiality breaches. The CVSS v3.1 base score for this vulnerability is 8.3, indicating a high level of severity.

## Recommendation

*   Apply the patch or upgrade to a version of Agno that addresses CVE-2026-10105 to eliminate the vulnerable code.
*   Deploy the Sigma rule "Detect CVE-2026-10105 Exploitation Attempt - Malicious Metadata in Agno ClickHouse DELETE Request" to identify potential exploitation attempts targeting the `delete_by_metadata()` method.
*   Review and sanitize all input data passed to the `delete_by_metadata()` method to prevent SQL injection attacks.
*   Implement strict input validation and output encoding to mitigate the risk of SQL injection vulnerabilities.
*   Monitor ClickHouse database logs for suspicious queries originating from the Agno application, as indicated by the "Detect Generic SQL Injection Attempts in ClickHouse Logs" Sigma rule.
