---
title: Critical SQL Injection Vulnerability in SAP Products (CVE-2026-27681)
slug: 2026-04-sap-sql-injection
description: A critical SQL injection vulnerability, CVE-2026-27681, affects SAP Business Planning and Consolidation (BPC) and SAP Business Warehouse (BW), potentially allowing attackers to execute arbitrary SQL commands and fully compromise affected systems.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sap
  - sql-injection
  - cve-2026-27681
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27681
    cvss: 9.9
  - id: CVE-2026-34256
    cvss: 7.1
    epss: 0.00036
  - id: CVE-2025-64775
    cvss: 7.5
    epss: 0.00193
  - id: CVE-2026-27674
    cvss: 6.1
    epss: 0.00054
  - id: CVE-2026-0512
    cvss: 6.1
    epss: 0.00069
references:
  - https://ccb.belgium.be/advisories/warning-critical-sql-injection-vulnerability-sap-products-cve-2026-27681-patch
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27681
  - https://support.sap.com/en/my-support/knowledge-base/security-notes-news/april-2026.html
  - https://me.sap.com/notes/3719353
rules:
  - title: Generic SQL Injection Attempt - URI Query
    description: Detects potential SQL injection attempts in URI queries based on common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Generic SQL Injection Attempt - POST Body
    description: Detects potential SQL injection attempts in HTTP POST requests based on common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On April 14, 2026, SAP released security patches addressing multiple vulnerabilities in its products, including a critical SQL injection vulnerability identified as CVE-2026-27681. This vulnerability affects SAP Business Planning and Consolidation (BPC) and SAP Business Warehouse (BW). The flaw stems from insufficient authorization checks, allowing a low-privilege authenticated user to execute arbitrary SQL commands. Successful exploitation could lead to unauthorized access to sensitive database information, modification of critical business data, and potentially a denial of service. The affected versions include HANABPC 810, BPC4HANA 300, SAP_BW 750, 752, 753, 754, 755, 756, 757, 758, and 816. In addition to CVE-2026-27681, SAP addressed other vulnerabilities, including CVE-2026-34256, CVE-2025-64775, CVE-2026-27674 and CVE-2026-0512.

## Attack Chain

1. An attacker gains low-privilege access to an SAP system, either through compromised credentials or an existing authorized account.
2. The attacker crafts a malicious SQL query designed to exploit CVE-2026-27681.
3. The attacker injects the malicious SQL query into an input field or parameter within the SAP Business Planning and Consolidation (BPC) or SAP Business Warehouse (BW) application.
4. Due to insufficient authorization checks, the application executes the injected SQL query.
5. The attacker leverages the executed SQL query to access sensitive database information, such as user credentials, financial data, or proprietary business information.
6. The attacker modifies critical business data, potentially altering financial records, supply chain information, or customer data.
7. The attacker could delete or manipulate data, leading to a denial of service, disrupting business operations.
8. The attacker achieves full compromise of the affected systems, potentially gaining complete control over the database and associated applications.

## Impact

Successful exploitation of CVE-2026-27681 can have severe consequences, including unauthorized access to sensitive database information, modification of critical business data, and potential denial of service. This could lead to significant financial losses, reputational damage, and disruption of critical business operations. The vulnerability impacts SAP Business Planning and Consolidation (BPC) and SAP Business Warehouse (BW), potentially affecting a wide range of organizations that rely on these systems for business planning, data warehousing, and analytics.

## Recommendation

*   Apply the security patches released by SAP for CVE-2026-27681 to vulnerable instances of SAP Business Planning and Consolidation (BPC) and SAP Business Warehouse (BW) with the highest priority after thorough testing, as recommended by SAP.
*   Deploy the generic SQL Injection detection rule to identify potential exploitation attempts in SAP webserver logs, tuning for your specific environment.
*   Monitor SAP systems for suspicious database activity, such as unauthorized data access or modification, as highlighted in the advisory.
*   Implement stricter authorization checks and input validation measures to prevent future SQL injection vulnerabilities, based on the description of CVE-2026-27681.
