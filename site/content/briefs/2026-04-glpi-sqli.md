---
title: GLPI SQL Injection Vulnerability (CVE-2026-29047)
slug: 2026-04-glpi-sqli
description: GLPI versions 10.0.0 before 10.0.24 and 11.0.6 are vulnerable to SQL Injection (CVE-2026-29047) via the logs export feature, allowing authenticated users to potentially execute arbitrary SQL commands.
date: "2026-04-06T15:17:07Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - glpi
  - sqli
  - cve-2026-29047
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-29047
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29047
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-3m49-qf92-vccr
rules:
  - title: Detect GLPI SQL Injection Attempt via Logs Export
    description: Detects potential SQL injection attempts targeting the GLPI logs export feature by monitoring for suspicious characters in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI SQL Injection via POST Request
    description: Detects potential SQL injection attempts targeting the GLPI via POST requests with SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

GLPI is a free asset and IT management software package.  CVE-2026-29047 affects GLPI versions 10.0.0 up to, but not including, 10.0.24, as well as version 11.0.6. An authenticated user can exploit a SQL injection vulnerability present in the logs export feature. Successful exploitation could allow an attacker to read sensitive data, modify database content, or even execute arbitrary commands on the underlying database server.  Organizations using vulnerable versions of GLPI should upgrade to versions 10.0.24 or 11.0.6 as soon as possible to mitigate the risk. This vulnerability highlights the importance of keeping software up to date with the latest security patches.

## Attack Chain

1. An attacker gains valid user credentials to a GLPI instance (versions 10.0.0 to 10.0.23 or 11.0.0 to 11.0.5).
2. The attacker authenticates to the GLPI web interface using the acquired credentials.
3. The attacker navigates to the "logs export" feature within the GLPI interface.
4. The attacker crafts a malicious SQL query and injects it into a parameter that is used when exporting the logs. This parameter is not properly sanitized.
5. The GLPI application processes the crafted SQL query without proper sanitization, leading to SQL injection.
6. The injected SQL query is executed against the GLPI database.
7. The attacker retrieves sensitive data from the database or modifies existing data.
8. The attacker escalates the attack, potentially gaining control of the underlying database server depending on database privileges.

## Impact

Successful exploitation of CVE-2026-29047 can lead to unauthorized access to sensitive information stored in the GLPI database, such as user credentials, asset information, and IT configuration details. An attacker could modify or delete critical data, disrupt IT operations, and potentially gain control over the entire GLPI system. This could impact all organizations utilizing the vulnerable GLPI version, potentially leading to data breaches and financial losses.

## Recommendation

*   Upgrade GLPI to version 10.0.24 or 11.0.6 to patch CVE-2026-29047 (references: advisory in Overview).
*   Implement database activity monitoring to detect and alert on suspicious SQL queries (references: Attack Chain step 6).
*   Review user access controls and enforce the principle of least privilege to limit the impact of compromised accounts (references: Attack Chain step 1).
*   Deploy the Sigma rule provided to detect potential exploitation attempts targeting the logs export feature (references: rules section).
