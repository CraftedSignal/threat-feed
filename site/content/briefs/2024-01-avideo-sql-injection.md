---
title: AVideo SQL Injection Vulnerability (CVE-2026-33651)
slug: 2024-01-avideo-sql-injection
description: AVideo versions up to 26.0 are vulnerable to time-based blind SQL injection via the `live_schedule_id` parameter in `remindMe.json.php`, allowing authenticated users to extract arbitrary database contents.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - sql-injection
  - cve-2026-33651
  - webserver
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33651
rules:
  - title: Detect AVideo SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the `remindMe.json.php` endpoint in AVideo by looking for SQL keywords in the `live_schedule_id` parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SQL Injection via Time-Based Delay
    description: Detects potential time-based SQL injection attempts targeting the `remindMe.json.php` endpoint in AVideo by looking for `SLEEP` or `WAITFOR DELAY` functions within the `live_schedule_id` parameter.
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

AVideo, an open-source video platform, is susceptible to a critical SQL injection vulnerability (CVE-2026-33651) affecting versions up to and including 26.0. The vulnerability lies within the `remindMe.json.php` endpoint, where the `$_REQUEST['live_schedule_id']` parameter is mishandled. Despite attempts to sanitize the input using `intval()` within intermediate functions, the original tainted variable remains unsanitized before being directly concatenated into a SQL `LIKE` clause within `Scheduler_commands::getAllActiveOrToRepeat()`. This flaw enables any authenticated user to perform time-based blind SQL injection attacks. The vulnerability was patched in commit 75d45780728294ededa1e3f842f95295d3e7d144. Successful exploitation could lead to unauthorized access and exfiltration of sensitive database information.

## Attack Chain

1. An attacker authenticates to the AVideo platform with valid credentials.
2. The attacker crafts a malicious HTTP request targeting the `remindMe.json.php` endpoint.
3. The attacker injects SQL code into the `live_schedule_id` parameter within the request. This parameter is passed unsanitized to the vulnerable function.
4. The `remindMe.json.php` script processes the request, passing the tainted `live_schedule_id` to `Scheduler_commands::getAllActiveOrToRepeat()`.
5. `Scheduler_commands::getAllActiveOrToRepeat()` concatenates the injected SQL code into a `LIKE` clause within a SQL query.
6. The application executes the malicious SQL query against the AVideo database.
7. The attacker uses time-based techniques to infer the results of the injected SQL query, extracting data bit by bit.
8. The attacker successfully exfiltrates sensitive information from the database, such as user credentials, configuration settings, or other confidential data.

## Impact

Successful exploitation of CVE-2026-33651 allows any authenticated user to perform time-based blind SQL injection attacks, leading to the complete compromise of the AVideo database. This can result in the exfiltration of sensitive data, including user credentials and system configurations. Given that AVideo is a video platform, the exposed data could also include information about video content, user activity, and potentially even the videos themselves. The number of affected installations is unknown.

## Recommendation

*   Apply the patch from commit 75d45780728294ededa1e3f842f95295d3e7d144 to remediate CVE-2026-33651.
*   Deploy the Sigma rule "Detect AVideo SQL Injection Attempt" to detect exploitation attempts against the `remindMe.json.php` endpoint.
*   Monitor web server logs for suspicious requests containing SQL syntax in the `live_schedule_id` parameter of the `remindMe.json.php` endpoint.
*   Implement input validation and sanitization for all user-supplied input to prevent SQL injection vulnerabilities.
