---
title: YesWiki Public Bazar API Unauthenticated SQL Injection (CVE-2026-52770)
slug: 2026-07-yeswiki-bazar-sqli
description: An unauthenticated attacker can exploit CVE-2026-52770, an SQL injection vulnerability in YesWiki's public Bazar entry-listing APIs, by manipulating numeric `query` or `queries` GET parameters, to use the application as a boolean oracle for inferring sensitive database contents like user accounts and password hashes.
date: "2026-07-09T21:11:12Z"
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
vendors:
  - YesWiki
products:
  - YesWiki (< 4.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: YesWiki’s public Bazar entry-listing APIs are vulnerable to unauthenticated SQL injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: An unauthenticated attacker can inject boolean SQL expressions and infer database contents from whether entries are returned.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An attacker can use public Bazar API endpoints as a boolean oracle to infer data accessible to the YesWiki database user. This may include user account data, password hashes, password recovery material, private wiki metadata, or other sensitive database contents.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: An attacker can use public Bazar API endpoints as a boolean oracle to infer data accessible to the YesWiki database user... infer database contents from whether entries are returned.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-qg78-vmvc-fhjw
rules:
  - title: Detects CVE-2026-52770 Exploitation - YesWiki Bazar SQL Injection
    description: Detects CVE-2026-52770 exploitation where an unauthenticated attacker attempts SQL injection via the 'query' or 'queries' GET parameters in YesWiki's public Bazar API, indicated by suspicious SQL keywords in a numeric context.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

YesWiki, an open-source wiki software, is vulnerable to an unauthenticated SQL injection, tracked as CVE-2026-52770, affecting versions prior to 4.6.6. This vulnerability resides in the public Bazar entry-listing APIs, specifically when processing numeric `query` or `queries` GET parameters. An attacker can craft malicious input containing boolean SQL expressions that are improperly handled, allowing direct insertion into the database query without sufficient quoting or validation. This enables an unauthenticated attacker to leverage the application as a boolean oracle, inferring sensitive information from the database, such as user account data, password hashes, and private wiki metadata, based on variations in API responses. The issue stems from the `SearchManager::buildQueriesConditions()` function in `tools/bazar/services/SearchManager.php` where `mysqli_real_escape_string()` is used, but the resulting string is embedded into a numeric context without enclosing quotes, thus reactivating SQL syntax.

## Attack Chain

1. An unauthenticated attacker identifies a YesWiki instance running an affected version (less than 4.6.6) that exposes public Bazar API endpoints, such as `/api/forms/{formId}/entries` or `/api/entries/bazarlist`.
2. The attacker crafts an HTTP GET request to one of these public API endpoints, including a `query` or `queries` parameter intended for a numeric Bazar field.
3. Within the `query` parameter, the attacker injects a boolean SQL payload, for example, `bf_age>100 OR (SELECT COUNT(*) FROM yeswiki_users)>0`.
4. The YesWiki application's `ApiController.php` parses the `query` parameter and passes it to `BazarListService::getEntries()` and subsequently `SearchManager::search()`.
5. The `SearchManager::buildQueriesConditions()` function processes the attacker's input, performing `mysqli_real_escape_string()` but then embedding the parameter directly into an SQL query within a numeric context without proper quoting.
6. The backend database executes the maliciously crafted SQL query, where the injected boolean expression evaluates to true or false, depending on the database's contents (e.g., whether `COUNT(*)` returns a value greater than zero).
7. The application's HTTP response (e.g., the number of entries returned or the presence of specific entries) varies based on the outcome of the boolean SQL expression, serving as a boolean oracle.
8. The attacker repeatedly sends modified requests, incrementally inferring sensitive database contents, such as user accounts, password hashes, and private wiki metadata, through this boolean blind SQL injection technique.

## Impact

This unauthenticated SQL injection allows an attacker to query and extract sensitive data from the YesWiki database. While there are no specific victim counts or sectors mentioned, the ability to infer database contents poses a severe risk. Attackers can potentially gain access to user credentials (including password hashes), internal wiki content, and other confidential metadata. If successful, this can lead to unauthorized access to the YesWiki application, privilege escalation, or further compromise of the underlying server infrastructure, depending on the privileges of the database user account.

## Recommendation

* Patch CVE-2026-52770 immediately by updating YesWiki to version 4.6.6 or higher.
* Deploy the provided Sigma rule to your SIEM to detect suspicious activity related to CVE-2026-52770.
* Monitor web server access logs for HTTP GET requests to `/api/` endpoints that contain unusual SQL keywords or boolean logic in `query` or `queries` parameters, as described in the detection rule.
* Implement Web Application Firewall (WAF) rules to detect and block SQL injection attempts against YesWiki public API endpoints.
