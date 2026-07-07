---
title: 'CVE-2026-14809: Unauthenticated SQL Injection in Prog Management System'
slug: 2026-07-prog-management-sql-injection
description: A SQL Injection vulnerability, identified as CVE-2026-14809, exists in the Prog Management System developed by PROG MIS, allowing unauthenticated remote attackers to inject arbitrary SQL commands to read database contents.
date: "2026-07-06T09:26:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web
  - cve
  - high-severity
vendors:
  - PROG MIS
products:
  - Prog Management System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated remote attackers to inject arbitrary SQL commands
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: to read database contents
    confidence_band: high
cves:
  - id: CVE-2026-14809
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14809
  - https://www.twcert.org.tw/en/cp-139-11026-3df18-2.html
rules:
  - title: Detects CVE-2026-14809 Exploitation — Unauthenticated SQL Injection Attempt
    description: Detects CVE-2026-14809 exploitation attempts through common SQL injection patterns in HTTP request parameters targeting the Prog Management System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-14809 details a critical SQL Injection vulnerability present in the Prog Management System, a product developed by PROG MIS. This flaw allows unauthenticated remote attackers to execute arbitrary SQL commands directly against the underlying database. The vulnerability specifically enables attackers to read sensitive database contents, potentially leading to the exfiltration of confidential information such as user credentials, system configurations, or proprietary data. The issue stems from improper neutralization of special elements used in SQL commands. This vulnerability, scored with a CVSS 3.1 Base Score of 7.5 (High), poses a significant risk to organizations utilizing the affected system, as it grants attackers broad access to data without requiring any prior authentication. The exploitation does not appear to be currently observed in the wild.

## Attack Chain

1.  An unauthenticated remote attacker identifies a publicly accessible instance of the Prog Management System.
2.  The attacker crafts a malicious HTTP request targeting a vulnerable web endpoint within the system.
3.  This request includes specially formed input containing SQL metacharacters (e.g., single quotes, comments, boolean conditions like `' OR 1=1--`) in a parameter expected to be used in a database query.
4.  The vulnerable application processes the attacker's input without adequate sanitization or parameterized queries.
5.  The malicious input is concatenated directly into a SQL statement that is then executed by the backend database.
6.  The injected SQL commands manipulate the original query to return database schema information, table names, and column data.
7.  The application returns the results of the modified query, exposing sensitive database contents to the attacker via the HTTP response.
8.  The attacker continues to refine their injected SQL commands to systematically extract additional sensitive data from the entire database.

## Impact

The successful exploitation of CVE-2026-14809 allows unauthenticated remote attackers to read the full contents of the database backing the Prog Management System. This can lead to the exposure of highly sensitive information, including but not limited to, customer data, administrative credentials, intellectual property, and internal operational data. For organizations, this means a significant data breach risk, potential regulatory penalties, reputational damage, and follow-on attacks facilitated by the exfiltrated information. The CVSS 3.1 score of 7.5 (High) reflects the severe confidentiality impact.

## Recommendation

*   Immediately patch the Prog Management System with the latest updates provided by PROG MIS to address CVE-2026-14809.
*   Deploy the Sigma rule below to your SIEM/detection platform to identify potential exploitation attempts against web servers running the Prog Management System.
*   Implement or update Web Application Firewall (WAF) rules to detect and block common SQL Injection attack patterns, complementing endpoint detection efforts.
*   Monitor web server logs for HTTP requests matching patterns indicative of SQL Injection attempts as highlighted by the detection rule.
