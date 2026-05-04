---
title: Shandong Hoteam PDM Product Data Management System SQL Injection Vulnerability
slug: 2026-05-hoteam-pdm-sqli
description: Shandong Hoteam Software PDM Product Data Management System up to version 8.3.9 is vulnerable to SQL injection via manipulation of the SortOrder argument in the GetQueryMachineGridOnePageData function of the /Base/BaseService.asmx/DataService file, allowing remote attackers to potentially execute arbitrary SQL commands.
date: "2026-05-04T05:16:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7727
  - webserver
vendors:
  - Shandong Hoteam Software
products:
  - PDM Product Data Management System (<= 8.3.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7727
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7727
  - https://en.hoteamsoft.com/pdm
  - https://vuldb.com/vuln/360902
rules:
  - title: Detect Hoteam PDM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the SortOrder parameter in Shandong Hoteam PDM Product Data Management System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Hoteam PDM BaseService Access
    description: Detects access to the BaseService endpoint, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Shandong Hoteam Software's PDM Product Data Management System before version 8.3.10 is susceptible to a SQL injection vulnerability. The vulnerability exists in the `/Base/BaseService.asmx/DataService` file, specifically affecting the `GetQueryMachineGridOnePageData` function. By manipulating the `SortOrder` argument, a remote attacker can inject malicious SQL queries into the system. Successful exploitation could lead to unauthorized data access, modification, or even complete system compromise. Organizations using versions prior to 8.3.10 are urged to upgrade immediately to mitigate the risk. This vulnerability was reported on May 4, 2026.

## Attack Chain

1.  Attacker identifies a vulnerable Shandong Hoteam PDM instance running a version prior to 8.3.10.
2.  The attacker crafts a malicious HTTP request targeting the `/Base/BaseService.asmx/DataService` endpoint.
3.  Within the HTTP request, the attacker modifies the `SortOrder` argument.
4.  The `SortOrder` argument is injected with SQL code.
5.  The application fails to properly sanitize the attacker-supplied SQL code.
6.  The application executes the attacker-controlled SQL query against the backend database.
7.  The attacker gains unauthorized access to sensitive data stored within the database.
8.  The attacker exfiltrates the data or uses it for further malicious activities.

## Impact

Successful exploitation of this SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands on the affected system. This can lead to unauthorized access to sensitive data, modification of data, or even complete compromise of the database server. Organizations using vulnerable versions of Shandong Hoteam PDM Product Data Management System could suffer significant data breaches, financial losses, and reputational damage. There are no specific victim counts or sector targeting available, but this could affect any organization utilizing the vulnerable PDM system.

## Recommendation

*   Upgrade Shandong Hoteam Software PDM Product Data Management System to version 8.3.10 or later to remediate the vulnerability as mentioned in the overview.
*   Implement the provided Sigma rule `Detect Hoteam PDM SQL Injection Attempt` to identify malicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious requests containing potentially malicious SQL syntax in the `SortOrder` parameter, as described in the attack chain.
*   Implement proper input validation and sanitization techniques to prevent SQL injection vulnerabilities in web applications, mitigating similar risks in the future.
