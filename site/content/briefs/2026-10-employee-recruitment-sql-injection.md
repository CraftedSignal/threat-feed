---
brief_id: brief-2026-10-25-employee-recruitment-sql-injection
event_id: brief-2026-10-25-employee-recruitment-sql-injection
revision: 1
activity_at: "2026-10-25T12:28:07Z"
title: 'krupalshah Employee Recruitment System: SQL Injection (CVE-2026-116050)'
slug: 2026-10-employee-recruitment-sql-injection
description: The krupalshah Employee Recruitment System contains a SQL injection vulnerability in the registration component, allowing remote attackers to manipulate database queries via the pemail parameter.
date: "2026-10-25T12:28:07Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:krupalshah:employee_recruitment_system:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-application
  - unmaintained-software
vendors:
  - krupalshah
products:
  - Employee Recruitment System (<= 922ff6d208278282e7c8e36d70d9ae356adec9fe)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument pemail leads to sql injection. The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-116050
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116050
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rules to block SQL injection patterns in the pemail parameter for the identified vulnerable application.
      owner: SOC
      due: 24h
      evidence: Vulnerability is publicly disclosed and remote-exploitable.
  hunt_leads:
    - lead: Inspect web server access logs for requests to /source/registerform3.php containing SQL injection payloads in the pemail parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability exists in the pemail argument of the specified file.
  mitigation_plan:
    - priority: immediate
      action: Decommission or isolate the krupalshah Employee Recruitment System due to lack of vendor support and publicly available exploit code.
      owner: IT Operations
      addresses: CVE-2026-116050
      evidence: Product is unmaintained and no patches are available.
---

A SQL injection vulnerability exists in the Registration component of the krupalshah Employee Recruitment System, specifically within the '/source/registerform3.php' file. The vulnerability is triggered by manipulating the 'pemail' argument. The exploit code is publicly disclosed. As the product uses a rolling release model and is currently unmaintained, there are no patches available. This vulnerability affects all versions up to the commit hash 922ff6d208278282e7c8e36d70d9ae356adec9fe.

## Impact

Successful exploitation allows remote attackers to perform unauthorized database queries, potentially leading to data exfiltration or manipulation.

## Recommendation

- Inventory all instances of the krupalshah Employee Recruitment System within the environment.
- Since no patch is available, implement web application firewall (WAF) rules to inspect and block requests to '/source/registerform3.php' containing SQL syntax characters (e.g., single quotes, comments, union statements) within the 'pemail' parameter.
- Evaluate the decommissioning of this unmaintained software as it no longer receives security updates.
