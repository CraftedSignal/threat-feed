---
title: Windmill CE/EE SQL Injection Vulnerability
slug: 2026-04-windmill-sqli
description: Windmill CE/EE versions 1.276.0 through 1.603.2 are vulnerable to SQL injection in the folder ownership management, allowing authenticated attackers to inject SQL through the owner parameter, leading to sensitive data access, token forgery, and arbitrary code execution.
date: "2026-04-07T17:16:27Z"
type: coverage
types:
  - coverage
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

Windmill CE and EE, versions 1.276.0 through 1.603.2, are susceptible to an SQL injection vulnerability (CVE-2026-23696) affecting the folder ownership management functionality. An authenticated attacker can exploit this flaw by injecting SQL code via the `owner` parameter. Successful exploitation allows the attacker to read sensitive information, including the JWT signing secret and administrative user identifiers. This access enables them to forge administrative tokens, ultimately leading to arbitrary code execution through the workflow execution endpoints. This vulnerability poses a significant risk to organizations using affected versions of Windmill, potentially leading to data breaches and system compromise.

## Attack Chain

1.  An attacker authenticates to the Windmill CE/EE instance.
2.  The attacker navigates to the folder ownership management section.
3.  The attacker crafts a malicious HTTP request to modify folder ownership, injecting SQL code into the `owner` parameter.
4.  The application fails to properly sanitize the input, passing the malicious SQL query to the database.
5.  The SQL injection allows the attacker to extract sensitive information from the database, such as the JWT signing secret and administrative user credentials.
6.  The attacker uses the extracted JWT signing secret to forge an administrative token.
7.  The attacker leverages the forged administrative token to authenticate to the workflow execution endpoint.
8.  The attacker executes arbitrary code on the server via the workflow execution endpoint, achieving remote code execution.

## Impact

Successful exploitation of CVE-2026-23696 can lead to complete compromise of the Windmill CE/EE instance. An attacker can gain unauthorized access to sensitive data, including credentials and internal application secrets. They can also execute arbitrary code on the server, potentially leading to data breaches, system downtime, and further lateral movement within the network. This vulnerability affects all organizations using Windmill CE/EE versions 1.276.0 through 1.603.2, and can result in significant financial and reputational damage.

## Recommendation

*   Upgrade Windmill CE/EE to version 1.603.3 or later to patch CVE-2026-23696 as per the vendor's release notes ([https://github.com/windmill-labs/windmill/releases/tag/v1.603.3](https://github.com/windmill-labs/windmill/releases/tag/v1.603.3)).
*   Deploy the Sigma rule `Detect Suspicious Windmill Folder Ownership Modification` to identify potential SQL injection attempts within HTTP requests to the folder ownership management endpoint.
*   Monitor web server logs for suspicious activity, such as SQL errors or unusual characters in the `owner` parameter of requests targeting the folder ownership management endpoint (webserver log source).
