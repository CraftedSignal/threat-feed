---
title: SQL Injection in SourceCodester Online Reviewer Management System
slug: 2026-09-sql-injection-online-reviewer
description: SourceCodester Online Reviewer Management System 1.0 is vulnerable to remote SQL injection via the 'Course' parameter, allowing unauthenticated attackers to manipulate database queries.
date: "2026-09-20T04:17:23Z"
lastmod: "2026-09-20T08:19:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:online_reviewer_management_system:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-vulnerability
  - web-application
  - vulnerability
vendors:
  - SourceCodester
products:
  - Online Reviewer Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-93959
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93959
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93972
rules:
  - title: Detects CVE-2026-93959 Exploitation - SQL Injection in btn_functions.php
    description: Detects attempts to exploit SQL injection in the 'Course' parameter of btn_functions.php by looking for common SQL injection keywords and syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-93972 Exploitation - SQL Injection in Online Reviewer Management System
    description: Detects exploitation attempts against CVE-2026-93972 by monitoring for SQL injection syntax in the courseID parameter within the vulnerable btn_functions.php endpoint.
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
    - IT Operations
  immediate_actions:
    - action: Apply web server access restrictions to the vulnerable directory.
      owner: IT Operations
      due: 24h
      evidence: Source confirms remote exploitation capability.
  hunt_leads:
    - lead: Search logs for 500-series errors or unusual query strings targeting /reviewer_0/admins/assessments/course/btn_functions.php
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit is publicly disclosed.
  mitigation_plan:
    - priority: immediate
      action: Disable access to the vulnerable directory until a patch is available.
      owner: IT Operations
      addresses: CVE-2026-93959
      evidence: Vulnerability allows remote SQL injection.
updates:
  - at: "2026-09-20T08:19:02Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-93972 Exploitation - SQL Injection in Online Reviewer Management System'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93972
---

SourceCodester Online Reviewer Management System version 1.0 contains a critical SQL injection vulnerability identified as CVE-2026-93959. The flaw exists within the 'btn_functions.php' script located in the '/reviewer_0/admins/assessments/course/' directory. An unauthenticated remote attacker can exploit this by sending a crafted HTTP request containing malicious SQL syntax within the 'Course' argument. Successful exploitation allows the attacker to manipulate the underlying database queries, which may lead to unauthorized data exfiltration, modification of database contents, or in some configurations, administrative access. Given that public exploit code is already disclosed, defenders should prioritize patching or restricting access to the affected web directory.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of the SourceCodester Online Reviewer Management System.
2. Attacker sends a crafted HTTP GET or POST request to '/reviewer_0/admins/assessments/course/btn_functions.php'.
3. Attacker injects malicious SQL payload into the 'Course' parameter.
4. The web server processes the request and passes the unsanitized input to the database backend.
5. The database executes the injected query, returning unauthorized data or performing requested modifications.
6. Attacker exfiltrates sensitive database content or establishes persistent access via database functions.

## Impact

The vulnerability allows unauthenticated remote attackers to compromise the integrity and confidentiality of the database. This can lead to the loss of user credentials, system configuration details, or other sensitive information hosted within the application. Organizations utilizing this software in production environments face a high risk of total database compromise if the application is internet-facing.

## Recommendation

* Immediate mitigation: Restrict access to the '/reviewer_0/admins/assessments/course/' directory via web server access controls (e.g., allowlisting IP addresses).
* Detection engineering: Deploy the web server detection rule below to monitor for SQL injection attempts against the identified endpoint.
* Patch management: Monitor the SourceCodester vendor site for an official security update addressing CVE-2026-93959 and apply it to all production instances of the Online Reviewer Management System.
