---
title: CI4MS .env File Injection Vulnerability (CVE-2026-39394)
slug: 2024-01-02-ci4ms-env-injection
description: CI4MS versions prior to 0.31.4.0 are vulnerable to .env file injection via the Install::index() controller due to insufficient input validation and bypassed CSRF protection, allowing attackers to inject arbitrary configuration directives.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ci4ms
  - codeigniter
  - env-injection
  - cve-2026-39394
vendors:
  - CI4MS
products:
  - CI4MS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1564
    technique_name: Hide Artifacts
cves:
  - id: CVE-2026-39394
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39394
rules:
  - title: Detect CI4MS .env Injection Attempt via Install Route
    description: Detects attempts to exploit the CI4MS .env injection vulnerability (CVE-2026-39394) by monitoring POST requests to the /install route containing newline characters in the 'host' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1564.001
    data_sources:
      - webserver
      - linux
  - title: Detect CI4MS .env File Modification with Suspicious Content
    description: Detects modification of the .env file in a CI4MS installation directory containing suspicious content, indicating potential exploitation of CVE-2026-39394.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1564.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CI4MS is a CodeIgniter 4-based CMS skeleton designed to provide a production-ready, modular architecture with features like RBAC authorization and theme support. Versions prior to 0.31.4.0 contain a critical vulnerability (CVE-2026-39394) within the Install::index() controller. This controller reads the 'host' POST parameter without proper validation and passes it directly to the `updateEnvSettings()` function. This function, in turn, uses `preg_replace()` to write the value into the .env file. The lack of newline character stripping in the input allows an attacker to inject arbitrary configuration directives. Furthermore, the installation routes have CSRF protection explicitly disabled, and the InstallFilter can be bypassed when the `cache('settings')` is empty, such as during initial deployment or after cache expiry. This vulnerability allows unauthenticated attackers to modify the application's configuration, leading to potentially complete system compromise. CI4MS deployments are vulnerable until upgraded to version 0.31.4.0 or later.

## Attack Chain

1. An unauthenticated attacker sends a POST request to the `/install` route with a malicious 'host' parameter.
2. The `Install::index()` controller receives the POST request.
3. The controller bypasses CSRF protection due to it being explicitly disabled.
4. The `InstallFilter` is bypassed because the `cache('settings')` is empty (e.g., on a fresh deployment).
5. The 'host' parameter, containing injected configuration directives with newline characters, is passed to the `updateEnvSettings()` function.
6. The `updateEnvSettings()` function uses `preg_replace()` to write the attacker-controlled 'host' parameter into the .env file without proper sanitization.
7. The injected configuration directives are written into the .env file, modifying the application's configuration.
8. The attacker can now leverage the modified configuration for further malicious activities, such as gaining unauthorized access, escalating privileges, or injecting malicious code.

## Impact

Successful exploitation of this vulnerability allows an attacker to inject arbitrary configuration directives into the .env file. This can lead to a wide range of consequences, including but not limited to: database credential compromise, modification of application behavior, remote code execution, and complete system takeover. The number of potential victims is dependent on the number of CI4MS deployments running vulnerable versions (pre-0.31.4.0). Targeted sectors are likely to be diverse, reflecting the broad range of applications for which CI4MS is used.

## Recommendation

*   Upgrade CI4MS to version 0.31.4.0 or later to patch CVE-2026-39394.
*   Monitor web server logs for POST requests to the `/install` route containing newline characters in the 'host' parameter to detect potential exploitation attempts. Implement the provided Sigma rules to detect this activity.
*   Implement strict input validation on all user-supplied data, especially for parameters that are used to modify configuration files.
*   Ensure that CSRF protection is enabled and functioning correctly for all sensitive routes, including installation routes.
