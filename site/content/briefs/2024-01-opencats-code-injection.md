---
title: OpenCATS PHP Code Injection Vulnerability (CVE-2026-27760)
slug: 2024-01-opencats-code-injection
description: Unauthenticated attackers can exploit a PHP code injection vulnerability in OpenCATS versions prior to commit 3002a29 by injecting malicious PHP code into the installer's AJAX endpoint, leading to arbitrary code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - php
  - opencats
  - cve-2026-27760
vendors:
  - OpenCATS
products:
  - OpenCATS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-27760
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27760
rules:
  - title: Detect OpenCATS installer code injection attempt
    description: Detects attempts to inject PHP code into the OpenCATS installer's databaseConnectivity parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect persistent PHP code execution via config.php modification
    description: Detects modifications to config.php containing injected PHP code.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-27760 is a critical PHP code injection vulnerability that affects OpenCATS, a web-based applicant tracking system, in versions prior to commit 3002a29. The vulnerability resides in the installer AJAX endpoint, specifically within the `databaseConnectivity` action parameter. Unauthenticated attackers can exploit this flaw by injecting arbitrary PHP code into this parameter. This injected code allows attackers to execute arbitrary commands on the server. The vulnerability is triggered during the initial setup phase, when the installation wizard is not yet complete and continues to execute on every subsequent page load. This vulnerability poses a significant risk to organizations using vulnerable versions of OpenCATS, as it can lead to complete system compromise, data theft, or denial of service.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP POST request to the OpenCATS installer AJAX endpoint (`/install/ajax.php`).
2. The request includes the `databaseConnectivity` action parameter.
3. The attacker injects PHP code into the `databaseConnectivity` parameter, breaking out of the `define()` string context in `config.php` with a single quote and statement separator.
4. The injected code is then processed by the server, leading to arbitrary PHP code execution within the context of the web server user.
5. The injected code persists because it's written to the `config.php` file.
6. Every subsequent page load executes the injected PHP code, even after the initial malicious request.
7. The attacker can use the code execution to install a web shell for persistent access.
8. With the web shell, the attacker can perform various malicious activities, including reading sensitive files, modifying the database, or pivoting to other systems on the network.

## Impact

Successful exploitation of CVE-2026-27760 allows unauthenticated attackers to execute arbitrary PHP code on the affected OpenCATS server. This can lead to complete system compromise, including the theft of sensitive applicant data, modification of application settings, and the installation of backdoors for persistent access. Given that OpenCATS handles applicant data, a successful attack could result in a significant data breach and reputational damage. The vulnerability exists in the installer and persists throughout subsequent page loads as long as the installation wizard remains incomplete, making it highly impactful.

## Recommendation

*   Upgrade OpenCATS to a version containing commit 3002a29 or later to remediate CVE-2026-27760.
*   Monitor web server logs for suspicious POST requests to `/install/ajax.php` containing PHP code in the `databaseConnectivity` parameter to detect exploitation attempts (see rule: "Detect OpenCATS installer code injection attempt").
*   Implement a Web Application Firewall (WAF) rule to block requests containing PHP code in the `databaseConnectivity` parameter.
*   Review and restrict access to the `/install/` directory after completing the installation process to prevent accidental or malicious access to the installer.
