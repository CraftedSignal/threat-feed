---
title: WWBN AVideo Unauthenticated SQL Injection Vulnerability (CVE-2026-33485)
slug: 2024-01-30-avideo-sqli
description: WWBN AVideo versions up to 26.0 are vulnerable to unauthenticated SQL injection via the RTMP `on_publish` callback, allowing attackers to extract sensitive database information.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - sqli
  - unauthenticated
  - cve-2026-33485
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
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33485
rules:
  - title: Detect AVideo Unauthenticated SQL Injection Attempt
    description: Detects potential SQL injection attempts against the AVideo /plugin/Live/on_publish.php endpoint by monitoring the $_POST['name'] parameter for SQL syntax.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: AVideo on_publish.php POST Request
    description: Detects POST requests to the on_publish.php endpoint, which could indicate exploitation attempts
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to a critical SQL injection flaw. Specifically, versions up to and including 26.0 are affected. The vulnerability resides in the RTMP `on_publish` callback, located at `plugin/Live/on_publish.php`, which is accessible without authentication. The `$_POST['name']` parameter, representing the stream key, is directly embedded into SQL queries within `LiveTransmitionHistory::getLatest()` and `LiveTransmition::keyExists()`. This direct interpolation, without proper sanitization or parameterized binding, allows an unauthenticated attacker to perform time-based blind SQL injection. Successful exploitation enables the attacker to extract the entire database content, potentially including user password hashes, email addresses, and other sensitive data. This vulnerability poses a significant risk to AVideo installations, potentially leading to data breaches and unauthorized access. A patch is available in commit af59eade82de645b20183cc3d74467a7eac76549.

## Attack Chain

1. An unauthenticated attacker sends a crafted RTMP `on_publish` request to the `/plugin/Live/on_publish.php` endpoint.
2. The request includes a malicious `$_POST['name']` parameter containing SQL injection payload.
3. The AVideo application receives the request and processes the `on_publish` callback.
4. The application calls `LiveTransmitionHistory::getLatest()` and `LiveTransmition::keyExists()`, passing the unsanitized `$_POST['name']` parameter.
5. The `$_POST['name']` parameter is directly interpolated into SQL queries executed against the AVideo database.
6. The attacker uses time-based blind SQL injection techniques to extract data bit-by-bit by observing the response time.
7. The attacker retrieves sensitive data such as user credentials (password hashes), email addresses, and other database contents.
8. The attacker uses the extracted credentials to gain unauthorized access to user accounts or the AVideo system.

## Impact

Successful exploitation of CVE-2026-33485 allows an unauthenticated attacker to extract the entire database content from vulnerable AVideo instances. This includes sensitive information such as user credentials (password hashes), email addresses, and potentially other confidential data stored within the database. The impact could range from unauthorized access to user accounts to a complete data breach, depending on the database contents. The number of affected AVideo installations is unknown, but the widespread use of the platform suggests a potentially large number of vulnerable systems. The lack of authentication required for exploitation makes this vulnerability particularly dangerous.

## Recommendation

*   Apply the patch provided in commit af59eade82de645b20183cc3d74467a7eac76549 or upgrade to a version of AVideo that includes this fix to remediate CVE-2026-33485.
*   Deploy the provided Sigma rule "Detect AVideo Unauthenticated SQL Injection Attempt" to identify potential exploitation attempts against the `/plugin/Live/on_publish.php` endpoint.
*   Implement a Web Application Firewall (WAF) rule to filter out malicious requests to `/plugin/Live/on_publish.php` containing suspicious SQL injection payloads in the `$_POST['name']` parameter.
