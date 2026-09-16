---
title: Chamilo LMS OS Command Injection Vulnerability (CVE-2026-35196)
slug: 2024-01-chamilo-os-command-injection
description: Chamilo LMS versions prior to 2.0.0-RC.3 are vulnerable to OS Command Injection via the _cid session variable in the export_all_certificates action, potentially leading to arbitrary command execution.
date: "2024-01-29T12:00:00Z"
lastmod: "2026-09-16T17:57:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:chamilo:chamilo_lms:*:*:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:alpha1:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:alpha2:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:alpha3:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:alpha4:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:alpha5:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:beta1:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:beta2:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:beta3:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:rc1:*:*:*:*:*:*
  - cpe:2.3:a:chamilo:chamilo_lms:2.0.0:rc2:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-35196&utm_source=rss&utm_medium=rss
tags:
  - cve-2026-35196
  - os command injection
  - chamilo lms
  - web application
vendors:
  - Chamilo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35196
    cvss: 8.8
    epss: 0.0176
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35196
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-35196&utm_source=rss&utm_medium=rss
rules:
  - title: Chamilo LMS OS Command Injection Attempt
    description: Detects potential OS Command Injection attempts in Chamilo LMS by identifying suspicious requests to gradebook.ajax.php with shell metacharacters in the _cid parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Chamilo LMS Suspicious Shell Execution via Webserver
    description: Detects potential OS Command Injection attempts resulting in shell execution from the webserver
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-09-16T17:57:21Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KX00007-CVE-2026-35196&utm_source=rss&utm_medium=rss
---

Chamilo LMS, an open-source learning management system, is susceptible to an OS Command Injection vulnerability (CVE-2026-35196) in versions prior to 2.0.0-RC.3. The vulnerability resides in the `main/inc/ajax/gradebook.ajax.php` endpoint, specifically within the `export_all_certificates` action. An attacker can exploit this flaw by manipulating the `_cid` session variable. Due to insufficient sanitization, the `_cid` value is directly concatenated into a `shell_exec()` command string. This allows an attacker to inject shell metacharacters and execute arbitrary commands on the underlying server. Successful exploitation could grant an attacker full access to read system files and credentials, modify the application and database, or disrupt server availability. Version 2.0.0-RC.3 addresses and resolves this vulnerability.

## Attack Chain

1. The attacker identifies a Chamilo LMS instance running a version prior to 2.0.0-RC.3.
2. The attacker gains a valid session, potentially through legitimate login or other means.
3. The attacker manipulates the `_cid` session variable, injecting shell metacharacters (e.g., `;`, `|`, `&&`) and a malicious command. This can be achieved through browser developer tools or intercepting/modifying HTTP requests.
4. The attacker triggers the `export_all_certificates` action in the `main/inc/ajax/gradebook.ajax.php` endpoint.
5. The application retrieves the attacker-controlled `_cid` value from the session using `api_get_course_id()`.
6. The application concatenates the unsanitized `_cid` value into a `shell_exec()` command.
7. The `shell_exec()` function executes the injected command on the server.
8. The attacker gains arbitrary command execution, allowing them to read sensitive files, modify the application, or disrupt the server.

## Impact

Successful exploitation of CVE-2026-35196 allows an attacker to execute arbitrary commands on the Chamilo LMS server. This could lead to the compromise of sensitive data, including system files, credentials, and database contents. An attacker can also modify the application, inject malicious code, or disrupt server availability, leading to a complete loss of confidentiality, integrity, and availability. The number of potential victims is related to the number of unpatched Chamilo LMS instances exposed to the internet. Sectors affected may include education and training organizations.

## Recommendation

*   Upgrade Chamilo LMS to version 2.0.0-RC.3 or later to patch CVE-2026-35196.
*   Deploy the Sigma rule "Chamilo LMS OS Command Injection Attempt" to your SIEM and tune for your environment to detect attempts to exploit the vulnerability via web server logs.
*   Monitor web server logs for suspicious requests to `main/inc/ajax/gradebook.ajax.php` containing shell metacharacters in the `_cid` parameter.
*   Implement input validation and sanitization for all user-supplied data, especially session variables, to prevent command injection attacks.
