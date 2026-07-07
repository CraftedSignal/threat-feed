---
title: OpenRemote Authenticated SQL Injection via Datapoint Crosstab Export
slug: 2026-07-openremote-sql-injection
description: An authenticated SQL injection vulnerability exists in the OpenRemote datapoint export API, allowing an attacker with asset creation/rename and datapoint export permissions to inject SQL commands via asset names, leading to arbitrary database execution and exfiltration of potentially cross-tenant data, with results returned in the normal ZIP/CSV export response.
date: "2026-07-06T21:58:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - data-exfiltration
  - web-application
vendors:
  - OpenRemote
products:
  - openremote-manager (< 1.26.0)
  - OpenRemote
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The injected query output is streamed back to the caller inside the normal ZIP/CSV export response. Receive injected SELECT results in the exported CSV contained in the ZIP response. The demonstrated impact is database data exfiltration.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cgfv-jrfp-2r7v
---

OpenRemote, an IoT solution platform, contains a critical authenticated SQL injection vulnerability in its datapoint export API, specifically within the crosstab export functionality. An attacker, requiring a valid authenticated session with permissions to create or rename assets and export their datapoints, can manipulate asset names to inject arbitrary SQL. This flaw stems from the application's practice of concatenating user-controlled asset display names directly into PostgreSQL `COPY` queries without proper escaping. The injected SQL is executed against the backend database, and its results are included within the legitimate ZIP/CSV export response, allowing for data exfiltration. This vulnerability, affecting `openremote-manager` versions prior to 1.26.0, poses a significant risk, particularly in multi-tenant environments where it could lead to unauthorized access and exfiltration of sensitive information across different tenants.

## Attack Chain

1.  An attacker obtains a valid authenticated session within the OpenRemote platform.
2.  The attacker uses their permissions to create a new asset or rename an existing one, embedding SQL metacharacters and desired injection payload into the asset's name.
3.  The attacker ensures this crafted asset has at least one exportable datapoint attribute, potentially writing a value to it if needed.
4.  The attacker initiates a CSV crosstab datapoint export request for the attribute associated with the specially crafted asset.
5.  The OpenRemote backend constructs a PostgreSQL `COPY` query, embedding the attacker-controlled asset name into SQL contexts without sufficient escaping.
6.  The database executes the malformed query, including the attacker's injected SQL statements (e.g., `SELECT` statements).
7.  The results of the injected `SELECT` query, along with normal datapoint data, are streamed back to the attacker within the exported CSV file contained in the ZIP response.
8.  The attacker extracts sensitive database information, such as `current_user`, `current_database()`, and `count(*)` from other tables, effectively exfiltrating data.

## Impact

The impact of this vulnerability is significant, particularly due to its high confidentiality risk. An authenticated attacker can exfiltrate arbitrary data from the backend PostgreSQL database. This includes potentially sensitive configuration data, user information, or operational data, and in multi-tenant deployments, it could expose data belonging to other tenants. While integrity and availability impacts were not demonstrated in the proof-of-concept, they remain a possibility depending on the application's database role privileges. The ease of exploitation, requiring only common asset management permissions, makes this a serious threat.

## Recommendation

*   Upgrade OpenRemote `openremote-manager` to version 1.26.0 or newer immediately to mitigate the SQL injection vulnerability as outlined in the `affected_products` section.
*   Review web application firewall (WAF) rules to detect and block SQL injection patterns in URL parameters or request bodies that target the datapoint export endpoint.
*   Implement strict input validation and parameterized queries in all application development, especially when handling user-controlled data that might be used in SQL queries, as detailed in the "Recommended Fix" section.
