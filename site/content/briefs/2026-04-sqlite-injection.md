---
title: dubydu sqlite-mcp SQL Injection Vulnerability (CVE-2026-7206)
slug: 2026-04-sqlite-injection
description: A SQL injection vulnerability exists in dubydu sqlite-mcp version 0.1.0 and earlier within the extract_to_json function allowing remote exploitation through manipulation of the output_filename argument.
date: "2026-04-28T01:16:02Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - cve-2026-7206
  - web-application
vendors:
  - dubydu
products:
  - sqlite-mcp
cves:
  - id: CVE-2026-7206
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7206
rules:
  - title: Detect Suspicious sqlite-mcp Requests
    description: Detects suspicious requests targeting the extract_to_json function of sqlite-mcp which may indicate a SQL injection attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect sqlite-mcp process spawning shell
    description: Detects sqlite-mcp spawning a shell process, potentially indicating command execution via SQL injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-7206, has been discovered in dubydu's sqlite-mcp software, affecting versions up to 0.1.0. The vulnerability resides within the `extract_to_json` function located in the `src/entry.py` file. An attacker can exploit this flaw by manipulating the `output_filename` argument, leading to the execution of arbitrary SQL commands. This vulnerability is remotely exploitable, meaning an attacker does not need local access to the system. A proof-of-concept exploit is publicly available, increasing the risk of active exploitation. Applying patch `a5580cb992f4f6c308c9ffe6442b2e76709db548` is the recommended remediation.

## Attack Chain

1.  An attacker identifies a vulnerable instance of dubydu sqlite-mcp running a version prior to the patched version.
2.  The attacker crafts a malicious request targeting the `extract_to_json` function in `src/entry.py`.
3.  The attacker injects SQL code into the `output_filename` argument of the request.
4.  The application processes the attacker-supplied `output_filename` argument without proper sanitization.
5.  The unsanitized input is passed directly to the underlying SQLite database engine.
6.  The SQLite database executes the injected SQL commands, potentially allowing the attacker to read sensitive data, modify data, or execute system commands, depending on the application's privileges and database configuration.
7.  The attacker retrieves the results of the injected SQL query, such as extracted data or confirmation of successful command execution.
8.  The attacker leverages the compromised database to achieve further objectives, such as data exfiltration or privilege escalation.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7206) can allow an attacker to execute arbitrary SQL queries against the underlying SQLite database. This could lead to the disclosure of sensitive information, modification of data, or even complete compromise of the application and the system it resides on. The CVSS v3.1 base score is 7.3, indicating a high severity vulnerability. Given the public availability of an exploit, affected systems are at an elevated risk of attack.

## Recommendation

*   Apply the provided patch `a5580cb992f4f6c308c9ffe6442b2e76709db548` to remediate CVE-2026-7206.
*   Implement input validation and sanitization measures to prevent SQL injection attacks, focusing on the `output_filename` parameter of the `extract_to_json` function.
*   Monitor web server logs for suspicious requests targeting the `extract_to_json` function using the Sigma rule `Detect Suspicious sqlite-mcp Requests`.
