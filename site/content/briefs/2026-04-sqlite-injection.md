---
title: dubydu sqlite-mcp SQL Injection Vulnerability (CVE-2026-7206)
slug: 2026-04-sqlite-injection
description: A SQL injection vulnerability exists in dubydu sqlite-mcp version 0.1.0 and earlier within the extract_to_json function allowing remote exploitation through manipulation of the output_filename argument.
date: "2026-04-28T01:16:02Z"
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

A SQL injection vulnerability, identified as CVE-2026-7206, has been discovered in dubydu's sqlite-mcp software, affecting versions up to 0.1.0. The vulnerability resides within the `extract_to_json` function located in the `src/entry.py` file. An attacker can exploit this flaw by manipulating the `output_filename` argument, leading to the execution of arbitrary SQL commands. This vulnerability is remotely exploitable, meaning an attacker does not need local access to the system. A…
