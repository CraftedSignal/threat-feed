---
title: ArcadeDB Cross-Database IDOR Vulnerability Allows Unauthorized Data Access
slug: 2026-07-arcadedb-idor
description: ArcadeDB server versions prior to 26.7.2 are vulnerable to a cross-database Insecure Direct Object Reference (IDOR) due to improper authorization checks in several HTTP handlers, enabling a user authorized for a specific database to gain full read and write access to other unauthorized databases by directly accessing specific API endpoints.
date: "2026-07-16T20:21:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - authorization-bypass
  - arcadedb
  - web-application
vendors:
  - ArcadeDB
products:
  - arcadedb-server (< 26.7.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: a user authorized only for DB 'a' calls POST /api/v1/batch/b, POST /api/v1/ts/b/write, GET /api/v1/ts/b/prom/api/v1/query, POST /api/v1/ts/b/query -> full read AND write of DB 'b' (200 OK).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x8mg-6r4p-87pf
rules:
  - title: Detect ArcadeDB Cross-Database IDOR Attempts
    description: Detects attempts to exploit the ArcadeDB cross-database IDOR vulnerability by requesting specific sensitive API endpoints that bypass authorization checks. This rule identifies access to vulnerable batch, time-series, Prometheus, and Grafana API paths.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 1
---

ArcadeDB, an open-source NoSQL graph database, contains a critical Insecure Direct Object Reference (IDOR) vulnerability (GHSA-x8mg-6r4p-87pf) affecting server versions prior to 26.7.2. This flaw allows a user with valid credentials, who is authorized to access only one database, to bypass authorization checks and gain full read and write access to other, unauthorized databases within the same ArcadeDB instance. The vulnerability stems from 14 specific HTTP handlers (including those for batch operations, time-series data, Prometheus, and Grafana integrations) which directly extend `AbstractServerHttpHandler` instead of the secure `DatabaseAbstractHandler`, failing to invoke the crucial `user.canAccessToDatabase()` function. Exploitation of this vulnerability grants attackers unauthorized control over sensitive data across different databases, posing a significant risk of data exfiltration, manipulation, or integrity compromise. This issue directly impacts organizations using ArcadeDB for multi-tenant or segmented data storage.

## Attack Chain

1. **Initial Authentication**: An attacker obtains valid user credentials for an ArcadeDB instance, successfully authenticating and gaining authorized access to at least one specific database (e.g., 'DB A').
2. **Identify Vulnerable Endpoints**: The attacker identifies specific ArcadeDB HTTP API endpoints, such as `/api/v1/batch/{db}`, `/api/v1/ts/{db}/write`, or `/api/v1/ts/{db}/prom/api/v1/query`, which are known to be affected by the IDOR vulnerability.
3. **Craft Malicious HTTP Request**: The attacker crafts an HTTP request (GET or POST) targeting one of the identified vulnerable endpoints. Crucially, the attacker substitutes the database identifier in the URL path parameter (e.g., `{db}`) from their authorized database ('DB A') to an unauthorized target database ('DB B').
4. **Authorization Bypass**: Upon receiving the request, the ArcadeDB server's vulnerable HTTP handler (e.g., PostBatchHandler or PostTimeSeriesWriteHandler) processes the `{database}` path parameter without invoking the necessary `user.canAccessToDatabase()` authorization check.
5. **Unauthorized Database Access**: The server proceeds to resolve and access the target database ('DB B') despite the attacker's lack of explicit authorization for it.
6. **Perform Unauthorized Operations**: The attacker successfully executes read (e.g., via `/api/v1/ts/b/prom/api/v1/query`) or write (e.g., via `/api/v1/batch/b` or `/api/v1/ts/b/write`) operations on the unauthorized 'DB B', receiving a "200 OK" HTTP status code.
7. **Data Exfiltration or Manipulation**: Through these unauthorized operations, the attacker gains full control over 'DB B', allowing for data exfiltration, modification, or deletion, leading to compromise of data confidentiality and integrity.

## Impact

Successful exploitation of this IDOR vulnerability allows an authenticated attacker to bypass authorization controls, gaining complete read and write access to any database within the ArcadeDB instance, regardless of their assigned permissions. This leads to a severe compromise of data confidentiality and integrity across all databases. Attackers can exfiltrate sensitive information, alter critical data, or even delete entire database contents. Organizations utilizing ArcadeDB for multi-tenant environments or to segregate data by user/department are particularly at risk, as an attacker with low-privilege access to one database could escalate their privileges to access all others.

## Recommendation

* **Patch ArcadeDB**: Immediately upgrade ArcadeDB server instances to version 26.7.2 or later to apply the necessary security fixes.
* **Monitor Webserver Logs**: Deploy the Sigma rule in this brief to your SIEM and monitor webserver logs for HTTP requests targeting the vulnerable `/api/v1/batch/` and `/api/v1/ts/` API endpoints.
* **Review Access Logs**: Periodically review webserver access logs for anomalous requests to the `/api/v1/batch/{db}` and `/api/v1/ts/{db}/*` paths, particularly for requests to database names that the originating user should not have access to.
