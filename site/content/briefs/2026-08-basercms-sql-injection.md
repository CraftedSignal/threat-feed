---
title: SQL Injection and Remote Code Execution in baserCMS
slug: 2026-08-basercms-sql-injection
description: Authenticated administrators can exploit a SQL injection vulnerability in baserCMS versions prior to 5.3.0, chaining it with a secondary code injection flaw to extract sensitive data and execute arbitrary PHP code.
date: "2026-08-20T15:15:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - baserCMS
products:
  - baserCMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: baserCMS before 5.3.0 contains a SQL injection vulnerability in BcDatabaseService.php that allows authenticated administrators to inject attacker-controlled table names.
    confidence_band: high
cves:
  - id: CVE-2026-76635
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76635
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch baserCMS to 5.3.0
      owner: IT Operations
      due: 24h
      evidence: baserCMS before 5.3.0 contains a SQL injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access to trusted personnel
      owner: IT Operations
      addresses: CVE-2026-76635
      evidence: Vulnerability requires authenticated administrator access
---

baserCMS versions prior to 5.3.0 are affected by a critical vulnerability that allows authenticated administrators to perform SQL injection attacks via the BcDatabaseService.php component. An attacker can inject arbitrary table names and configuration values during sequence updates, CSV exports, or table management operations. This vulnerability is particularly dangerous because it can be chained with a secondary backup restore flaw, where schema files containing malicious PHP code execute unconditionally upon being loaded. By combining these, an attacker can plant malicious table names and trigger error-based SQL injection, enabling the retrieval of database versioning information, schema structure, and sensitive data from the underlying PostgreSQL backend. This chain effectively allows a privileged user to escalate their access to arbitrary code execution and full data exfiltration.

## Impact

Successful exploitation allows an attacker with administrator access to achieve Remote Code Execution (RCE) on the host server and full unauthorized access to the database contents. This impacts the confidentiality, integrity, and availability of the entire CMS installation and the associated PostgreSQL database backend.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Upgrade all instances of baserCMS to version 5.3.0 or higher to remediate the underlying SQL injection and code execution flaws.
- Audit administrative access logs for suspicious activity involving sequence updates or CSV export operations in BcDatabaseService.php.
- Monitor PostgreSQL error logs for unusual error-based injection patterns or unexpected database schema queries occurring outside of normal CMS maintenance operations.
