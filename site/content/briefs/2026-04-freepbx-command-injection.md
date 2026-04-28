---
title: FreePBX API Module Command Injection Vulnerability (CVE-2026-40520)
slug: 2026-04-freepbx-command-injection
description: FreePBX api module version 17.0.8 and prior contain a command injection vulnerability in the initiateGqlAPIProcess() function, allowing authenticated users to execute arbitrary commands via crafted GraphQL mutations.
date: "2026-04-21T13:16:20Z"
type: coverage
types:
  - coverage
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

FreePBX, a widely used open-source PBX (Private Branch Exchange) system, is vulnerable to a command injection flaw within its API module. Specifically, versions 17.0.8 and earlier are affected by CVE-2026-40520. The vulnerability resides in the `initiateGqlAPIProcess()` function, where GraphQL mutation input fields are directly passed to the `shell_exec()` function without proper sanitization or escaping. This allows an authenticated attacker with a valid bearer token to inject and execute arbitrary commands on the underlying host operating system as the web server user. The attack vector involves sending a specially crafted GraphQL `moduleOperations` mutation containing backtick-wrapped commands within the `module` field. Successful exploitation grants the attacker the ability to compromise the FreePBX server and potentially pivot to other internal systems.

## Attack Chain

1. The attacker authenticates to the FreePBX API using a valid bearer token.
2. The attacker crafts a GraphQL `moduleOperations` mutation request.
3. Within the `module` field of the mutation, the attacker injects a command using backticks (e.g., `\`id\` `).
4. The attacker sends the malicious GraphQL request to the `/api` endpoint.
5. The `initiateGqlAPIProcess()` function processes the request without proper sanitization.
6. The injected command is passed to the `shell_exec()` function within `Api.class.php`.
7. The `shell_exec()` function executes the injected command on the FreePBX server as the web server user (e.g., `www-data`, `apache`).
8. The attacker gains arbitrary command execution on the server.

## Impact

Successful exploitation of this command injection vulnerability (CVE-2026-40520) allows an attacker to execute arbitrary commands on the FreePBX server with the privileges of the web server user. This can lead to complete compromise of the PBX system, allowing the attacker to eavesdrop on calls, modify call routing, steal sensitive data, install malware, and potentially pivot to other systems on the network. Given the critical role of PBX systems in business communications, a successful attack can disrupt operations, damage reputation, and result in significant financial losses.

## Recommendation

*   Upgrade the FreePBX API module to a version greater than 17.0.8 to patch CVE-2026-40520.
*   Deploy the Sigma rule `Detect FreePBX GraphQL Command Injection` to identify exploitation attempts by detecting backticks in GraphQL mutation requests.
*   Monitor web server logs for POST requests to the `/api` endpoint containing GraphQL mutations with backtick-wrapped commands to detect command injection attempts.
*   Implement input validation and sanitization measures for all GraphQL input fields to prevent command injection vulnerabilities.
