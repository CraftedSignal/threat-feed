---
title: Windmill CE/EE SQL Injection Vulnerability
slug: 2026-04-windmill-sqli
description: Windmill CE/EE versions 1.276.0 through 1.603.2 are vulnerable to SQL injection in the folder ownership management, allowing authenticated attackers to inject SQL through the owner parameter, leading to sensitive data access, token forgery, and arbitrary code execution.
date: "2026-04-07T17:16:27Z"
severities:
  - critical
tags:
  - sql-injection
  - rce
  - windmill
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-23696
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23696
  - https://www.vulncheck.com/advisories/windmill-file-ownership-handling-sqli-rce
  - https://github.com/windmill-labs/windmill/releases/tag/v1.603.3
rules:
  - title: Detect Suspicious Windmill Folder Ownership Modification
    description: Detects potential SQL injection attempts in requests to modify Windmill folder ownership by looking for unusual characters or SQL keywords in the owner parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Windmill Workflow Execution with Forged Token
    description: Detects potential workflow execution using forged tokens after SQL injection in Windmill.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Windmill CE and EE, versions 1.276.0 through 1.603.2, are susceptible to an SQL injection vulnerability (CVE-2026-23696) affecting the folder ownership management functionality. An authenticated attacker can exploit this flaw by injecting SQL code via the `owner` parameter. Successful exploitation allows the attacker to read sensitive information, including the JWT signing secret and administrative user identifiers. This access enables them to forge administrative tokens, ultimately leading to…
