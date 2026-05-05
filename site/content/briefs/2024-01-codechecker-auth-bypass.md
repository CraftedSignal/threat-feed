---
title: CodeChecker Authentication Bypass Vulnerability
slug: 2024-01-codechecker-auth-bypass
description: An authentication bypass vulnerability exists in CodeChecker for certain API calls, allowing unauthenticated users to execute function calls with arbitrary arguments, potentially granting superuser permissions to an attacker.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - privilege-escalation
  - web-application
vendors:
  - Ericsson
products:
  - codechecker (<= 6.27.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-25660
    cvss: 9.8
    epss: 0.0007
references:
  - https://github.com/advisories/GHSA-4v9x-cqc5-j645
  - https://github.com/Ericsson/codechecker/releases/tag/v6.27.4
rules:
  - title: Detect CodeChecker Authentication Bypass Attempt
    description: Detects unauthorized POST requests to CodeChecker Authentication API endpoints, indicating a potential authentication bypass attempt.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect CodeChecker addPermission API Abuse
    description: Detects successful calls to the addPermission API from unexpected source IPs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An authentication bypass vulnerability has been discovered in CodeChecker versions 6.27.3 and earlier. The vulnerability exists due to improper authentication checks when accessing specific API endpoints under the `/Authentication` path. This allows unauthenticated users to execute functions such as `getAuthorisedNames`, `getPermissionsForUser`, `hasPermission`, `addPermission`, and `removePermission` with arbitrary arguments. Successful exploitation of this vulnerability can allow an attacker with a CodeChecker user to acquire superuser permissions, leading to complete control over the CodeChecker instance. The issue was reported on May 5, 2026, and a patch is available in version 6.27.4.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable CodeChecker instance running a version prior to 6.27.4.
2. The attacker crafts a POST request to a vulnerable endpoint, such as `/v6.27/Authentication@addPermission`, without providing valid authentication credentials.
3. The attacker includes parameters in the POST request to assign elevated privileges to an existing user account within CodeChecker.
4. The CodeChecker server, due to the authentication bypass, processes the request without proper authentication checks.
5. The `addPermission` function is executed, granting the specified user account the requested permissions, potentially including superuser privileges.
6. The attacker logs in to CodeChecker with the compromised user account.
7. The attacker leverages the newly acquired superuser permissions to perform administrative tasks, such as modifying code analysis rules or accessing sensitive data.
8. The attacker gains full control over the CodeChecker instance, potentially compromising the security of code analysis and development workflows.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over a CodeChecker instance. An attacker with a CodeChecker user can effectively acquire superuser permissions. This could lead to unauthorized access to sensitive code analysis data, modification of code analysis rules, or the introduction of malicious code into the development pipeline. The number of victims is currently unknown, but any organization using CodeChecker versions 6.27.3 or earlier is potentially affected.

## Recommendation

*   Upgrade CodeChecker to version 6.27.4 or later to patch CVE-2026-25660.
*   Deploy the Sigma rule `Detect CodeChecker Authentication Bypass Attempt` to your SIEM to detect exploitation attempts by monitoring for unauthorized access attempts to the Authentication API.
*   Monitor web server logs for POST requests to `/Authentication` endpoints from unauthenticated users, as highlighted in the example log entries in the overview.
