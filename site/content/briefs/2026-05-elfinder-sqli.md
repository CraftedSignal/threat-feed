---
title: elFinder MySQL Volume Driver SQL Injection (CVE-2026-44521)
slug: 2026-05-elfinder-sqli
description: An authenticated SQL injection vulnerability (CVE-2026-44521) exists in the elFinder MySQL volume driver (`elFinderVolumeMySQL`) allowing any logged-in user, including read-only users, to inject SQL through a crafted `target` file hash leading to unauthorized data disclosure and denial of service.
date: "2026-05-11T16:13:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - elfinder
vendors:
  - studio-42
products:
  - elfinder (<= 2.1.67)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-c3gj-q88f-7hqj
rules:
  - title: Detect elFinder SQL Injection Attempt via Target Parameter
    description: Detects CVE-2026-44521 exploitation — SQL injection attempts in elFinder through the `target` parameter, indicated by SQL-related keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect elFinder MySQL Volume Driver in Use
    description: Detects the usage of the MySQL volume driver in elFinder configurations, which is a prerequisite for CVE-2026-44521 exploitation.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The elFinder file manager is vulnerable to SQL injection within its MySQL volume driver (`elFinderVolumeMySQL`). This flaw, identified as CVE-2026-44521, permits any authenticated user, even those with read-only privileges on the affected volume, to inject SQL commands by manipulating the `target` parameter with a crafted file hash. This vulnerability specifically impacts elFinder installations configured to utilize the MySQL volume driver, while those employing the default `LocalFileSystem` driver remain unaffected. The vulnerability exists due to the system's failure to validate decoded file hashes as valid MySQL object identifiers before their inclusion in queries.

## Attack Chain

1.  Attacker authenticates to elFinder with a valid user account.
2.  Attacker identifies the elFinder instance is using the MySQL volume driver.
3.  Attacker crafts a malicious `target` parameter containing a SQL injection payload encoded as a file hash.
4.  Attacker sends a request to elFinder with the crafted `target` parameter, triggering one of the vulnerable functions: `cacheDir()`, `_joinPath()`, `_stat()`, or `_fopen()`.
5.  elFinder decodes the file hash without proper validation.
6.  The decoded SQL injection payload is incorporated into a MySQL query.
7.  The injected SQL command executes against the MySQL database, potentially extracting sensitive data or causing a denial of service.
8.  Attacker retrieves the leaked data or observes the degraded performance due to the denial-of-service condition.

## Impact

Successful exploitation allows an authenticated user, even one with read-only access, to disclose data accessible to the configured MySQL account, including file contents stored by the driver and database metadata. It can also trigger denial of service through expensive or broad query results. The severity depends on the MySQL account privileges. Affected packages include `composer/studio-42/elfinder` versions 2.1.67 and earlier.

## Recommendation

*   Upgrade `composer/studio-42/elfinder` to a version later than 2.1.67 to patch CVE-2026-44521.
*   Deploy the Sigma rule "Detect elFinder SQL Injection Attempt via Target Parameter" to identify exploitation attempts by monitoring requests with potentially malicious file hashes in the `target` parameter.
*   Consider using the default `LocalFileSystem` driver if the `MySQL` volume driver is not a requirement to mitigate CVE-2026-44521.
