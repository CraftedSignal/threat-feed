---
title: SQL Injection in CubeCart 6.7.4
slug: 2026-08-cubecart-sqli
description: An authenticated SQL injection vulnerability in CubeCart 6.7.4 allows administrative users to execute arbitrary SQL commands due to improper sanitization of the download_expire parameter.
date: "2026-08-31T14:04:53Z"
lastmod: "2026-08-31T14:05:17Z"
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
  - xss
  - injection
  - cve-2026-54644
vendors:
  - CubeCart
products:
  - CubeCart (6.7.4)
  - CubeCart (<= 6.7.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows the injection of malicious comma-separated SQL syntax to manipulate database queries.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Stored Cross-Site Scripting (XSS) vulnerability exists in the product management panel of CubeCart 6.7.4, where product descriptions bypass global input filters and sanitization controls.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: When clients or other administrators view the affected product page on either the public storefront or the administration panel, the payload executes within their active session.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52664
  - https://github.com/cubecart/v6/security/advisories/GHSA-hvmw-v8gc-4c29
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54647
  - https://www.exploit-db.com/exploits/52662
  - https://github.com/cubecart/v6/security/advisories/GHSA-43f6-gfcf-wj9c
  - https://www.exploit-db.com/exploits/52661
  - https://github.com/cubecart/v6/security/advisories/GHSA-v55x-fh73-29vq
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
  - title: Detect CVE-2026-54644 Exploitation - XSS Attempt via Anchor Tags
    description: Detects attempts to inject malicious JavaScript via anchor tag attributes in web application requests, indicative of CVE-2026-54644 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 2
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
updates:
  - at: "2026-08-31T14:05:05Z"
    level: L1
    summary: added coverage for CubeCart (<= 6.7.4)
    sources:
      - exploit-db
    source_urls:
      - https://www.exploit-db.com/exploits/52662
  - at: "2026-08-31T14:05:17Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-54644 Exploitation - XSS Attempt via Anchor Tags'
    sources:
      - exploit-db
    source_urls:
      - https://www.exploit-db.com/exploits/52661
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
