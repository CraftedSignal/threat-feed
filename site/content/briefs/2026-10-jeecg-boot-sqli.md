---
brief_id: brief-2026-10-30-jeecg-boot-sqli
event_id: brief-2026-10-30-jeecg-boot-sqli
revision: 1
activity_at: "2026-10-30T16:51:50Z"
title: 'Jeecg-Boot: Unauthenticated SQL Injection (CVE-2023-1454)'
slug: 2026-10-jeecg-boot-sqli
description: Jeecg-Boot version 3.5.0 contains an unauthenticated SQL injection vulnerability in the /jmreport/qurestSql endpoint, enabling remote attackers to execute error-based SQL queries and disclose sensitive database information.
date: "2026-10-30T16:51:50Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:jeecg:jeecg-boot:3.5.0:*:*:*:*:*:*:*
  - cpe:2.3:a:jeecg:jeecg_boot:3.5.0:*:*:*:*:*:*:*
vendors:
  - Jeecg
products:
  - Jeecg-Boot (3.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker, by constructing specially crafted strings, can ultimately obtain sensitive information from the target database.
    confidence_band: high
cves:
  - id: CVE-2023-1454
    cvss: 6.3
    epss: 0.36072
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BUGFOR-PINGS-CVE-2023-1454
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BUGFOR-PINGS-CVE-2023-1454&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2023-1454 Exploitation - SQL Injection in /jmreport/qurestSql
    description: Detects attempts to exploit CVE-2023-1454 by identifying POST requests to the jmreport/qurestSql endpoint with characteristic SQL injection syntax in the JSON request body.
    platform: sigma
    severity: critical
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
    - IT Operations
  immediate_actions:
    - action: Inventory and patch all instances of Jeecg-Boot v3.5.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2023-1454 is rated CVSS 9.8
  hunt_leads:
    - lead: Review web logs for POST requests to /jmreport/qurestSql containing SQL syntax
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability exists in the jmreport/qurestSql endpoint
  mitigation_plan:
    - priority: immediate
      action: Implement WAF filtering for malicious SQL injection strings on the /jmreport/qurestSql path
      owner: SOC
      addresses: CVE-2023-1454
      evidence: SQL injection vulnerability due to improper input sanitization
---

Jeecg-Boot version 3.5.0 is vulnerable to an unauthenticated SQL injection via the /jmreport/qurestSql endpoint. The vulnerability is caused by improper sanitization of the id parameter within the JSON request body. An attacker can exploit this flaw by sending a crafted POST request to the aforementioned path, potentially resulting in unauthorized sensitive data exposure via error-based SQL injection.

## Impact
Successful exploitation allows an unauthenticated remote attacker to perform error-based SQL injection, leading to the unauthorized disclosure of database contents.

## Recommendation
- Inventory all internet-facing instances of Jeecg-Boot to identify version 3.5.0 deployments.
- Apply security patches or update Jeecg-Boot to a non-vulnerable version immediately.
- Implement Web Application Firewall (WAF) rules to inspect and block POST requests to /jmreport/qurestSql containing SQL metacharacters (e.g., OR, AND, updatexml, concat, like) in the id parameter.
