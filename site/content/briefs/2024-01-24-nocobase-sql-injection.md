---
title: NocoBase SQL Injection via Missing Validation on Update Endpoint
slug: 2024-01-24-nocobase-sql-injection
description: A SQL injection vulnerability exists in nocobase plugin-collection-sql versions 2.0.32 and earlier due to missing validation on the sqlCollection:update endpoint, allowing attackers with collection management permissions to execute arbitrary SQL queries and exfiltrate data.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - nocobase
vendors:
  - nocobase
products:
  - plugin-collection-sql
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-wrwh-c28m-9jjh
rules:
  - title: Detect NocoBase SQL Injection via Update Endpoint
    description: Detects attempts to exploit the SQL injection vulnerability in NocoBase by monitoring POST requests to the sqlCollection:update endpoint with suspicious SQL queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect NocoBase Collection Creation with Blocked SQL Keywords
    description: Detects attempts to create NocoBase collections with SQL queries containing blocked keywords.
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

The `@nocobase/plugin-collection-sql` plugin for NocoBase is vulnerable to SQL injection. Specifically, the `checkSQL()` validation function, responsible for preventing dangerous SQL keywords, is applied to the `collections:create` and `sqlCollection:execute` endpoints, but is absent from the `sqlCollection:update` endpoint. This oversight allows an attacker with collection management permissions (specifically, the `pm.data-source-manager.collection-sql` snippet) to inject arbitrary SQL code. The attack involves creating a SQL collection with benign SQL, updating it with malicious SQL bypassing validation, and subsequently querying the collection to execute the injected SQL. This vulnerability, confirmed to affect versions 2.0.32 and earlier, can lead to unauthorized data access, privilege escalation, and potentially remote code execution on the database server.

## Attack Chain

1.  The attacker gains collection management permissions, possibly through compromised credentials or exploiting another vulnerability.
2.  The attacker crafts a request to the `collections:create` endpoint to create a new SQL collection with a benign SQL query, such as `"SELECT 1 as id"`.
3.  The NocoBase server processes the request, and the `checkSQL()` function validates the SQL query and allows the collection creation.
4.  The attacker crafts a malicious request to the `sqlCollection:update` endpoint, targeting the newly created collection. The request contains a SQL payload designed to extract sensitive data, such as `"SELECT * FROM users"`, or execute malicious functions.
5.  The NocoBase server processes the update request, but crucially, the `checkSQL()` function is not called, allowing the malicious SQL payload to be saved to the collection configuration.
6.  The attacker crafts a request to the `<collection_name>:list` endpoint to query the updated collection.
7.  The NocoBase server executes the stored malicious SQL query against the database.
8.  The database returns the results of the malicious query, potentially containing sensitive data (e.g., user credentials), which is then returned to the attacker.

## Impact

Successful exploitation of this SQL injection vulnerability can have severe consequences. Attackers can exfiltrate sensitive data, including user credentials and password hashes, leading to confidentiality breaches. Furthermore, by using database-specific functions such as `pg_read_file` or `LOAD_FILE`, attackers can potentially read arbitrary files from the database server's filesystem. The vulnerability can also be exploited for privilege escalation, allowing attackers to gain unauthorized access to other databases or execute arbitrary code on the database server. While the number of victims is unknown, any NocoBase instance running a vulnerable version of the `@nocobase/plugin-collection-sql` plugin is susceptible to this attack.

## Recommendation

*   Apply the fix suggested in the advisory by adding `checkSQL()` to the `update` action within the `@nocobase/plugin-collection-sql` plugin.
*   Deploy the Sigma rule `Detect NocoBase SQL Injection via Update Endpoint` to detect attempts to exploit this vulnerability by monitoring HTTP requests to the `sqlCollection:update` endpoint.
*   Upgrade to a patched version of `@nocobase/plugin-collection-sql` that includes the necessary validation on the `update` action, mitigating the risk of SQL injection.
*   Implement the more comprehensive defense measures recommended in the advisory, such as centralizing validation and strengthening the blocklist of dangerous SQL keywords to prevent future vulnerabilities.
