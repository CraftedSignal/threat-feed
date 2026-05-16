---
title: LayerBB 1.1.4 SQL Injection Vulnerability (CVE-2021-47954)
slug: 2026-05-layerbb-sql-injection
description: LayerBB version 1.1.4 is vulnerable to SQL injection via the search_query parameter, allowing unauthenticated attackers to inject SQL code and extract sensitive database information.
date: "2026-05-16T16:20:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2021-47954
  - web-application
vendors:
  - LayerBB
products:
  - LayerBB 1.1.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2021-47954
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47954
  - https://www.exploit-db.com/exploits/49593
  - https://www.vulncheck.com/advisories/layerbb-sql-injection-via-search-query-parameter
rules:
  - title: Detect LayerBB SQL Injection Attempt via Search Query
    description: Detects CVE-2021-47954 exploitation — SQL injection attempts in LayerBB 1.1.4 via the search_query parameter in a POST request to /search.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect LayerBB SQL Injection Attempt via Search Query (URI Encoding)
    description: Detects CVE-2021-47954 exploitation — SQL injection attempts in LayerBB 1.1.4 via the search_query parameter in a POST request to /search.php with URI encoded characters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

LayerBB version 1.1.4 is susceptible to an SQL injection vulnerability (CVE-2021-47954) that allows unauthenticated attackers to manipulate database queries. This vulnerability arises from the insufficient sanitization of the `search_query` parameter, enabling attackers to inject arbitrary SQL code through crafted POST requests to `/search.php`. Successful exploitation could lead to the extraction of sensitive database information, potentially compromising the entire LayerBB installation. This poses a significant risk to organizations using this version of LayerBB, as attackers could gain unauthorized access to confidential data.

## Attack Chain

1.  The attacker identifies a vulnerable LayerBB 1.1.4 instance.
2.  The attacker crafts a malicious POST request targeting the `/search.php` endpoint.
3.  The POST request includes a `search_query` parameter containing SQL injection payloads, such as `CASE WHEN` statements.
4.  The vulnerable application fails to properly sanitize the `search_query` parameter.
5.  The injected SQL code is executed within the context of the database query.
6.  The attacker extracts sensitive database information, such as user credentials or application data.
7.  The extracted information is sent back to the attacker.
8.  The attacker leverages the compromised data to gain further access or control over the LayerBB installation or related systems.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2021-47954) can lead to the complete compromise of the LayerBB 1.1.4 installation. Attackers can extract sensitive information, including user credentials, personal data, and potentially other confidential application data. This can result in data breaches, identity theft, and reputational damage for the affected organization.

## Recommendation

*   Apply any available patches or updates for LayerBB to address CVE-2021-47954.
*   Deploy the Sigma rule `Detect LayerBB SQL Injection Attempt via Search Query` to identify potential exploitation attempts in web server logs.
*   Implement input validation and sanitization measures on the `search_query` parameter to prevent SQL injection attacks.
*   Monitor web server logs for suspicious POST requests to `/search.php` containing SQL injection payloads.
*   Review and harden database security configurations to limit the impact of potential SQL injection vulnerabilities.
