---
title: Remote SQL Injection Vulnerability in DeDeCMS
slug: 2026-08-dedecms-sqli
description: DeDeCMS version 53_1_UTF8 is vulnerable to a remote SQL injection attack via the 'sql' argument in /plus/advancedsearch.php, for which public exploit code is available.
date: "2026-08-20T03:09:15Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - DeDeCMS 53_1_UTF8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-76783
    cvss: 7.3
rules:
  - title: Detect CVE-2026-76783 - SQL Injection in DeDeCMS
    description: Detects exploitation attempts against the /plus/advancedsearch.php endpoint by searching for SQL injection keywords in the 'sql' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the SQL injection detection rule to web application monitoring
      owner: Detection Engineering
      due: 24h
      evidence: Public exploit code availability for CVE-2026-76783
  mitigation_plan:
    - priority: immediate
      action: Disable access to /plus/advancedsearch.php if not required or implement WAF filtering for the 'sql' parameter
      owner: IT Operations
      addresses: CVE-2026-76783
      evidence: Public exploit availability
---

A remote SQL injection vulnerability (CVE-2026-76783) has been identified in DeDeCMS version 53_1_UTF8. The flaw resides within the /plus/advancedsearch.php file, where the 'sql' argument is insufficiently sanitized before being processed in a backend database query. This vulnerability allows remote, unauthenticated attackers to inject and execute arbitrary SQL commands against the underlying database. The vulnerability has been disclosed publicly, and functional exploit code is available, increasing the risk of exploitation by malicious actors targeting this specific version of the CMS.

## Impact

Successful exploitation allows remote attackers to execute arbitrary SQL queries, which may result in unauthorized data exfiltration, database manipulation, or complete compromise of the application data. The vulnerability is rated with a CVSS v3.1 score of 7.3, reflecting its potential for impact on Confidentiality, Integrity, and Availability.

## Recommendation

- Immediately audit web server logs for requests targeting '/plus/advancedsearch.php' containing suspicious SQL syntax within the 'sql' parameter.
- Review the application code for the vulnerable '/plus/advancedsearch.php' script and implement parameterized queries to neutralize the SQL injection vector.
- Deploy the Sigma rule provided in this brief to monitor for exploitation attempts against this endpoint.
