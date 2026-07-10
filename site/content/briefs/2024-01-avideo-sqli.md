---
title: AVideo Platform Unauthenticated SQL Injection Vulnerability
slug: 2024-01-avideo-sqli
description: AVideo platform versions before 26.0 are vulnerable to unauthenticated SQL injection via the getAllCategories() method in objects/category.php due to insufficient sanitization of the doNotShowCats parameter, potentially leading to arbitrary code execution.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - sqli
  - cve-2026-33352
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33352
rules:
  - title: AVideo SQL Injection Attempt via doNotShowCats Parameter
    description: Detects potential SQL injection attempts targeting the doNotShowCats parameter in AVideo's objects/category.php.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: AVideo SQL Injection Attempt - Backslash Escaped Single Quote
    description: Detects potential SQL injection attempts in AVideo using backslash-escaped single quotes within the doNotShowCats parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to an unauthenticated SQL injection vulnerability affecting versions prior to 26.0. Specifically, the vulnerability resides within the `getAllCategories()` method located in the `objects/category.php` file. The `doNotShowCats` request parameter, intended to filter categories, undergoes insufficient sanitization, merely stripping single quotes. Attackers can bypass this weak protection using backslash escape techniques, manipulating SQL string boundaries to inject malicious code. The application's global input filters, managed within `objects/security.php`, do not adequately cover this parameter, further exacerbating the risk. AVideo version 26.0 addresses this critical flaw with a patch. Successful exploitation allows attackers to execute arbitrary SQL queries, potentially compromising the entire application and its underlying data.

## Attack Chain

1. An attacker identifies an AVideo instance running a version prior to 26.0.
2. The attacker crafts a malicious HTTP request targeting the `objects/category.php` endpoint.
3. The crafted request includes the `doNotShowCats` parameter containing SQL injection payload with backslash escapes to bypass sanitization (e.g., `\'`).
4. The AVideo server receives the request and passes the unsanitized `doNotShowCats` parameter to the `getAllCategories()` method.
5. The application constructs a SQL query using the attacker-controlled input without proper escaping.
6. The injected SQL code is executed against the AVideo database.
7. The attacker can potentially read sensitive database information, modify data, or execute arbitrary operating system commands via SQL injection.
8. The attacker achieves complete compromise of the AVideo platform, potentially exfiltrating data or using the compromised server for further malicious activities.

## Impact

Successful exploitation of this SQL injection vulnerability allows unauthenticated attackers to execute arbitrary SQL queries on the AVideo platform's database. This could lead to the disclosure of sensitive information, modification or deletion of data, or even complete compromise of the server. The CVSS v3.1 base score of 9.8 reflects the high severity of this vulnerability. Organizations using vulnerable versions of AVideo are at risk of data breaches, service disruption, and potential legal repercussions.

## Recommendation

*   Immediately upgrade AVideo instances to version 26.0 or later to patch CVE-2026-33352.
*   Implement a web application firewall (WAF) rule to detect and block SQL injection attempts targeting the `doNotShowCats` parameter in `objects/category.php`.
*   Deploy the Sigma rule provided below to your SIEM to detect exploitation attempts based on HTTP request patterns.
*   Review and enhance input validation and sanitization routines within the AVideo application, paying close attention to user-supplied parameters used in SQL queries.
