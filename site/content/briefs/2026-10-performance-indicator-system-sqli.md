---
title: SQL Injection in SourceCodester Performance Indicator System
slug: 2026-10-performance-indicator-system-sqli
description: SourceCodester Performance Indicator System 1.0 contains an unauthenticated SQL injection vulnerability via the prodcategory parameter, allowing remote attackers to execute arbitrary SQL queries.
date: "2026-10-13T04:32:13Z"
lastmod: "2026-10-13T06:33:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:performance_indicator_system:1.0:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
  - injection
  - sql-injection
  - sourcecodester
  - web-application-security
  - cve
vendors:
  - SourceCodester
products:
  - Performance Indicator System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely via the prodcategory argument.
    confidence_band: high
cves:
  - id: CVE-2026-108964
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108964
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108967
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108968
rules:
  - title: Detect CVE-2026-108964 SQL Injection Attempt
    description: Detects potential SQL injection attempts against the Performance Indicator System by identifying SQL metacharacters in the prodcategory parameter of the addproduct.php script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-108967 Exploitation - SQL Injection in Performance Indicator System
    description: Detects potential SQL injection attempts targeting the edit_credit.php file in SourceCodester Performance Indicator System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect exploitation attempts against CVE-2026-108964.
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-108964 description
  mitigation_plan:
    - priority: immediate
      action: Identify and sanitize inputs for the 'prodcategory' argument in the '/opils/admin/addproduct.php' file.
      owner: IT Operations
      addresses: CVE-2026-108964
      evidence: NVD vulnerability details
updates:
  - at: "2026-10-13T06:33:06Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-108967 Exploitation - SQL Injection in Performance Indicator System'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108967
  - at: "2026-10-13T06:33:13Z"
    level: L2
    summary: added coverage for Performance Indicator System (1.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108968
---

SourceCodester Performance Indicator System version 1.0 is affected by a SQL injection vulnerability identified as CVE-2026-108964. The vulnerability exists within the file /opils/admin/addproduct.php and specifically impacts the 'prodcategory' argument. An unauthenticated remote attacker can supply maliciously crafted input to this parameter to manipulate database queries. This flaw arises from improper neutralization of special elements used in an SQL command before passing the input to the database management system. Publicly available exploit code increases the risk of successful exploitation by unauthorized actors attempting to gain unauthorized access to or extract data from the application database.

## Impact

Successful exploitation of this vulnerability allows an attacker to interact directly with the backend database. This may lead to the unauthorized disclosure, modification, or deletion of sensitive information stored within the application, such as user credentials, system configuration details, or internal performance data. Given the administrative context of the vulnerable script, the impact may extend to full database compromise.

## Recommendation

1. Review application logs for HTTP POST requests to /opils/admin/addproduct.php that contain SQL syntax characters in the 'prodcategory' parameter.
2. Implement strict input validation and parameterization for all user-supplied data in the Performance Indicator System codebase to prevent SQL injection.
3. Restrict access to the /opils/admin/ directory to authenticated administrators only, if business requirements permit.
4. Consult the vendor or the source software provider for patches addressing CVE-2026-108964 in version 1.0.
