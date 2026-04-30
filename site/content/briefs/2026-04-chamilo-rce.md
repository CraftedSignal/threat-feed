---
title: Chamilo LMS Unauthenticated Remote Code Execution via Configuration Injection (CVE-2026-33618)
slug: 2026-04-chamilo-rce
description: Chamilo LMS versions prior to 2.0.0-RC.3 are vulnerable to remote code execution (RCE) via eval injection, where an authenticated administrator can inject arbitrary PHP code into platform settings that is then executed when any user (including unauthenticated) requests the /platform-config/list endpoint.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - chamilo
  - rce
  - eval-injection
  - cve-2026-33618
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-33618
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33618
  - https://github.com/chamilo/chamilo-lms/commit/f2c382c94a3f153a4d7e5ce5686c5a219fd09b3b
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-hp4w-jmwc-pg7w
rules:
  - title: Chamilo Suspicious PlatformConfig Access
    description: Detects suspicious access to the /platform-config/list endpoint which could indicate attempts to trigger CVE-2026-33618 after an attacker has injected malicious settings.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Chamilo Eval Based Code Execution
    description: Detects potential code execution via eval() within Chamilo LMS by monitoring for spawned PHP processes from the web server user with suspicious command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Chamilo LMS is a widely used open-source learning management system. CVE-2026-33618 affects versions prior to 2.0.0-RC.3. The vulnerability lies within the `PlatformConfigurationController::decodeSettingArray()` method, which unsafely uses PHP's `eval()` function to parse platform settings retrieved from the database. An attacker who has already gained administrative access to the Chamilo LMS platform can inject arbitrary PHP code into these settings. This injected code is then executed whenever *any* user, including unauthenticated users, makes a request to the `/platform-config/list` endpoint. This allows for unauthenticated remote code execution, making it a critical vulnerability for organizations using affected versions of Chamilo LMS.

## Attack Chain

1.  Attacker gains administrative access to the Chamilo LMS instance (potentially through a separate vulnerability or compromised credentials).
2.  Attacker navigates to the platform configuration settings page within the Chamilo LMS admin panel.
3.  Attacker injects malicious PHP code into a configurable setting field. This code is designed to execute arbitrary commands on the server.
4.  The injected PHP code is saved to the Chamilo LMS database.
5.  An unauthenticated user makes a request to the `/platform-config/list` endpoint.
6.  The `PlatformConfigurationController::decodeSettingArray()` method is called to process the platform settings from the database.
7.  The `eval()` function executes the attacker's injected PHP code.
8.  The attacker achieves remote code execution on the Chamilo LMS server, enabling them to potentially compromise the entire system and connected networks.

## Impact

Successful exploitation of CVE-2026-33618 allows an attacker to execute arbitrary PHP code on the Chamilo LMS server. This can lead to full system compromise, data exfiltration, defacement, or denial-of-service. Given that Chamilo LMS is used by educational institutions and organizations worldwide, a successful attack could impact thousands of users and expose sensitive student or employee data. The vulnerability's ease of exploitation, requiring only admin access and an unauthenticated request to a specific endpoint, makes it a highly attractive target for malicious actors.

## Recommendation

*   Immediately upgrade Chamilo LMS instances to version 2.0.0-RC.3 or later to patch CVE-2026-33618.
*   Monitor web server logs for requests to the `/platform-config/list` endpoint originating from unusual IP addresses or user agents using the Sigma rule `Chamilo_Suspicious_PlatformConfig_Access`.
*   Implement the Sigma rule `Chamilo_Eval_Based_Code_Execution` to detect potential exploitation attempts based on unusual PHP processes spawned from the web server.
*   Review and audit all Chamilo LMS administrative accounts for suspicious activity to prevent initial access to vulnerable configuration settings.
