---
title: SQL Injection in Readabler Plugin for WordPress
slug: 2026-08-readabler-sqli
description: The Readabler WordPress plugin is vulnerable to unauthenticated SQL injection in versions prior to 2.0.18, allowing remote attackers to extract sensitive database content.
date: "2026-08-25T12:08:17Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - Readabler Plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries.
    confidence_band: high
cves:
  - id: CVE-2026-78576
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78576
  - https://patchstack.com/database/wordpress/plugin/readabler/vulnerability/wordpress-readabler-plugin-2-0-18-sql-injection-vulnerability
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/baaa9688-dfdc-4ab2-b033-fe2b13a42e77?source=cve
rules:
  - title: Detect CVE-2026-78576 Exploitation - Potential SQL Injection in Readabler
    description: Detects potential SQL injection attempts targeting WordPress plugins by identifying common SQL syntax characters in URI query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Readabler plugin to version 2.0.18
      owner: IT Operations
      due: 24h
      evidence: Plugin version must be >= 2.0.18 to mitigate CVE-2026-78576
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin
      owner: IT Operations
      addresses: CVE-2026-78576
      evidence: NVD vulnerability disclosure
---

The Readabler plugin for WordPress contains an unauthenticated SQL injection vulnerability (CVE-2026-78576) affecting all versions prior to 2.0.18. The flaw exists due to improper input sanitization and a lack of parameterized queries when handling user-supplied parameters. Because the vulnerability is reachable without authentication, remote, unauthenticated attackers can manipulate SQL queries executed by the application. Successful exploitation enables the exfiltration of sensitive information from the site's database, posing a high risk to data confidentiality. Organizations utilizing the Readabler plugin are advised to verify their installed version and upgrade to 2.0.18 or higher to remediate this vulnerability.

## Impact

Successful exploitation allows unauthenticated attackers to perform SQL injection attacks, leading to unauthorized access to sensitive database information. This may include user credentials, configuration details, or other private data stored within the WordPress database. Given the ubiquity of WordPress installations, this vulnerability represents a significant risk for organizations managing public-facing web infrastructure.

## Recommendation

- Update the Readabler plugin for WordPress to version 2.0.18 or later immediately.
- Audit web server access logs for anomalous HTTP requests containing SQL keywords (e.g., SELECT, UNION, SLEEP) targeting WordPress plugin endpoints.
- Deploy the Sigma rule provided below to monitor for potential SQL injection patterns targeting web applications.
