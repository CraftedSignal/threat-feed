---
title: FreePBX API Module Command Injection Vulnerability (CVE-2026-40520)
slug: 2026-04-freepbx-command-injection
description: FreePBX api module version 17.0.8 and prior contain a command injection vulnerability in the initiateGqlAPIProcess() function, allowing authenticated users to execute arbitrary commands via crafted GraphQL mutations.
date: "2026-04-21T13:16:20Z"
severities:
  - high
tags:
  - command-injection
  - freepbx
  - graphql
  - cve-2026-40520
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40520
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40520
  - https://github.com/FreePBX/api/blob/5f194e39a47e5481e8947f9694304d32724175f6/Api.class.php#L546C1-L554C3
  - https://github.com/FreePBX/api/blob/5f194e39a47e5481e8947f9694304d32724175f6/ApiGqlHelper.class.php#L34C1-L36C136
  - https://github.com/FreePBX/api/commit/5f194e39a47e5481e8947f9694304d32724175f6
  - https://www.vulncheck.com/advisories/freepbx-api-module-command-injection-via-graphql
rules:
  - title: Detect FreePBX GraphQL Command Injection
    description: Detects potential command injection attempts in FreePBX GraphQL mutations by looking for backticks in the request body.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect shell_exec Usage in FreePBX API Class
    description: Detects usage of shell_exec function within FreePBX Api.class.php which can indicate command injection vulnerabilities
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreePBX, a widely used open-source PBX (Private Branch Exchange) system, is vulnerable to a command injection flaw within its API module. Specifically, versions 17.0.8 and earlier are affected by CVE-2026-40520. The vulnerability resides in the `initiateGqlAPIProcess()` function, where GraphQL mutation input fields are directly passed to the `shell_exec()` function without proper sanitization or escaping. This allows an authenticated attacker with a valid bearer token to inject and execute…
