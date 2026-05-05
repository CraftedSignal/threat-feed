---
title: AWP Classifieds WordPress Plugin SQL Injection Vulnerability
slug: 2026-05-awp-classifieds-sqli
description: The AWP Classifieds plugin for WordPress is vulnerable to SQL Injection via the 'regions' parameter array keys in versions up to, and including, 4.4.5, potentially allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-05T03:15:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin
vendors:
  - WordPress
products:
  - AWP Classifieds plugin for WordPress (<= 4.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5100
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5100
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/7908d167-f831-4ed0-b754-2b390b5c3b2c?source=cve
rules:
  - title: Detect AWP Classifieds SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the AWP Classifieds plugin via the 'regions' parameter in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AWP Classifieds SQL Injection via POST
    description: Detects potential SQL injection attempts targeting the AWP Classifieds plugin via the 'regions' parameter using POST method.
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

The AWP Classifieds plugin for WordPress, a popular plugin used to create classified ads websites, contains a critical SQL Injection vulnerability. This flaw, identified as CVE-2026-5100, affects versions up to and including 4.4.5. The vulnerability resides within the handling of the 'regions' parameter array keys, where insufficient input sanitization and inadequate SQL query preparation allow unauthenticated attackers to inject arbitrary SQL code. Successful exploitation of this vulnerability can lead to the unauthorized extraction of sensitive data stored in the WordPress database. Given the widespread use of WordPress and the AWP Classifieds plugin, this vulnerability poses a significant risk to websites relying on the plugin for classifieds functionality.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress website using a vulnerable version of the AWP Classifieds plugin (<=4.4.5).
2. The attacker crafts a malicious HTTP request targeting the page search functionality.
3. The attacker injects SQL code into the 'regions' parameter array keys within the crafted request.
4. The vulnerable code fails to properly sanitize the injected SQL code.
5. The application executes the attacker-controlled SQL query against the WordPress database.
6. The attacker is able to extract sensitive information, such as user credentials or other confidential data, from the database.
7. The attacker may use the extracted information to further compromise the WordPress website or related systems.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-5100) in the AWP Classifieds plugin could allow unauthenticated attackers to extract sensitive information from the affected WordPress database. This may include user credentials, personal data, or other confidential business information. The compromise of this information can lead to identity theft, financial fraud, and reputational damage. There is no victim count available, but all sites running vulnerable versions of this plugin are at risk.

## Recommendation

*   Upgrade the AWP Classifieds plugin to the latest version to patch CVE-2026-5100.
*   Deploy the provided Sigma rule `Detect AWP Classifieds SQL Injection Attempt` to detect exploitation attempts in web server logs.
*   Implement a web application firewall (WAF) with rules to filter out malicious SQL injection payloads targeting the 'regions' parameter.
*   Review and harden database access controls to limit the potential impact of successful SQL injection attacks.
