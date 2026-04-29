---
title: CKAN Unauthenticated SQL Injection in datastore_search_sql
slug: 2024-01-ckan-sql-injection
description: An unauthenticated SQL injection vulnerability in CKAN's `datastore_search_sql` function allows attackers to access private resources and PostgreSQL system information, affecting versions prior to 2.10.10 and versions 2.11.0 through 2.11.4.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - ckan
  - sql-injection
  - vulnerability
vendors:
  - pip
products:
  - ckan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-h7j7-3rx6-xvcg
  - https://docs.ckan.org/en/2.11/maintaining/configuration.html#ckan-datastore-sqlsearch-enabled
  - https://docs.ckan.org/en/2.11/extensions/plugin-interfaces.html#ckan.plugins.interfaces.IAuthFunctions
rules:
  - title: Detect SQL Injection Attempts in CKAN datastore_search_sql
    description: Detects potential SQL injection attempts targeting the `datastore_search_sql` endpoint in CKAN.  This rule identifies requests containing common SQL keywords and syntax within the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Authorization Bypass Attempts in CKAN datastore_search_sql via SQL Injection
    description: Detects potential authorization bypass attempts in CKAN by identifying suspicious parameters and SQL keywords in requests to the `datastore_search_sql` endpoint, which may lead to accessing unauthorized resources.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical SQL injection vulnerability exists within the `datastore_search_sql` function of CKAN, an open-source data management system. This vulnerability allows unauthenticated attackers to inject arbitrary SQL queries, potentially leading to unauthorized access to sensitive data, including private resources and PostgreSQL system information. The vulnerability affects CKAN versions prior to 2.10.10 and versions 2.11.0 up to and including 2.11.4.  Successful exploitation can compromise the confidentiality and integrity of the CKAN instance and its underlying database. The issue was reported by Arvin Shivram of Brutecat Security and patched in CKAN versions 2.10.10 and 2.11.5.  Organizations using vulnerable versions of CKAN are at risk of data breaches and unauthorized access to critical system information.

## Attack Chain

1.  The attacker identifies a CKAN instance running a vulnerable version (prior to 2.10.10 or 2.11.0-2.11.4).
2.  The attacker crafts a malicious HTTP request targeting the `datastore_search_sql` endpoint.
3.  The malicious request contains a SQL injection payload within the parameters expected by `datastore_search_sql`.
4.  CKAN's `datastore_search_sql` function fails to properly sanitize the input, allowing the injected SQL code to be executed against the PostgreSQL database.
5.  The injected SQL query retrieves sensitive data, such as private resource information, user credentials, or PostgreSQL system details.
6.  The attacker extracts the compromised data from the HTTP response.
7.  The attacker may use the compromised credentials to gain further access to the CKAN instance and its associated systems.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to unauthorized access to sensitive data stored within the CKAN DataStore, including private resources and user credentials. Attackers can also gain access to PostgreSQL system information, potentially leading to further system compromise. The number of affected organizations is unknown, but any organization running a vulnerable version of CKAN is at risk. If successful, the attack can lead to data breaches, financial losses, and reputational damage.

## Recommendation

*   Upgrade CKAN instances to version 2.10.10 or 2.11.5 to remediate CVE-2026-42031.
*   As a temporary workaround, disable the DataStore SQL search by setting `ckan.datastore.sqlsearch.enabled = false` in the CKAN configuration, as mentioned in the overview.
*   Monitor web server logs for suspicious requests targeting the `datastore_search_sql` endpoint, looking for SQL syntax within the query parameters using the Sigma rules provided below.
