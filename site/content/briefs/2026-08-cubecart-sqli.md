---
title: SQL Injection in CubeCart 6.7.4
slug: 2026-08-cubecart-sqli
description: An authenticated SQL injection vulnerability in CubeCart 6.7.4 allows administrative users to execute arbitrary SQL commands due to improper sanitization of the download_expire parameter.
date: "2026-08-31T14:04:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - webapps
  - sqli
  - cube-cart
vendors:
  - CubeCart
products:
  - CubeCart (6.7.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows the injection of malicious comma-separated SQL syntax to manipulate database queries.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52664
  - https://github.com/cubecart/v6/security/advisories/GHSA-hvmw-v8gc-4c29
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54647
rules:
  - title: Detects CVE-2026-54647 Exploitation - SQL Injection via download_expire
    description: Detects potential SQL injection attempts against the CubeCart administrative settings endpoint by monitoring for SQL control characters in the download_expire parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade CubeCart to version 6.7.5 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states 6.7.5 is the fixed version.
  enrichment_needed:
    - item: In-the-wild exploit activity
      owner: CTI
      reason: Monitor for real-world abuse of this CVE to prioritize response.
      evidence: None observed.
  mitigation_plan:
    - priority: immediate
      action: Upgrade CubeCart to 6.7.5.
      owner: IT Operations
      addresses: CVE-2026-54647
      evidence: Vendor advisory confirms patch availability.
  gaps:
    - Telemetry coverage for POST body content in webserver logs.
---

CubeCart version 6.7.4 is affected by an authenticated SQL injection vulnerability, identified as CVE-2026-54647. The vulnerability exists within the administrative settings interface, specifically in the file `admin/sources/settings.index.inc.php`. The application fails to properly sanitize the `download_expire` parameter when processing POST requests to save administrative settings. Because the application uses an unsafe concatenation method to build database queries, an authenticated administrative user can inject SQL syntax by including commas and other SQL control characters in the payload. This vulnerability allows an attacker to manipulate the `UPDATE` SQL statements executed by the application, potentially leading to unauthorized modification of database settings or other database-level actions.

## Attack Chain

1. Attacker obtains valid administrative credentials for the target CubeCart instance.
2. Attacker logs into the CubeCart administrative dashboard.
3. Attacker navigates to the administrative Settings page.
4. Attacker initiates a save request for the system settings.
5. Attacker intercepts the HTTP POST request using a proxy tool.
6. Attacker modifies the `download_expire` parameter to include malicious SQL syntax, such as "1, expire=0 WHERE 1=1-- -".
7. The application processes the tainted input and executes the injected SQL command against the database.
8. Unauthorized changes are applied to the database configuration or data.

## Impact

Successful exploitation allows an authenticated administrative attacker to manipulate arbitrary columns within the database settings tables. This can result in unauthorized changes to system configurations or potentially facilitate lateral movement and further data compromise within the underlying database.

## Recommendation

Prioritized actions for security teams:
- Patch CubeCart to version 6.7.5 or later immediately, as this version contains the fix for CVE-2026-54647.
- Audit administrative access logs for suspicious account activity that precedes configuration changes.
- Review database access logs for evidence of malformed SQL queries originating from the administrative settings endpoint.
- Disable or restrict access to the administrative dashboard to trusted internal IP addresses only.
