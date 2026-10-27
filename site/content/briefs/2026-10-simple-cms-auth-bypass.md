---
brief_id: brief-2026-10-27-simple-cms-auth-bypass
event_id: brief-2026-10-27-simple-cms-auth-bypass
revision: 1
activity_at: "2026-10-27T01:52:30Z"
title: 'code-projects Simple Content Management System: Missing Authorization (CVE-2026-116623)'
slug: 2026-10-simple-cms-auth-bypass
description: An authorization bypass vulnerability in the Admin Interface of code-projects Simple Content Management System 1.0 allows remote attackers to manipulate the addnews argument to perform unauthorized actions.
date: "2026-10-27T01:52:30Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:code-projects:simple_content_management_system:1.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - cms
  - authorization-bypass
vendors:
  - code-projects
products:
  - Simple Content Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The manipulation of the argument addnews results in missing authorization. The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-116623
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116623
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Restrict external access to /web/admin/ via web application firewall or server configuration
      owner: SOC
      due: 24h
      evidence: Vulnerability in Admin Interface component of the CMS
  hunt_leads:
    - lead: Identify requests to /web/admin/welcome.php with addnews parameter
      technique_id: T1505
      data_needed:
        - web server access logs (cs-uri-stem, cs-uri-query)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggered via the addnews argument in /web/admin/welcome.php
---

CVE-2026-116623 describes a missing authorization vulnerability in code-projects Simple Content Management System version 1.0. The vulnerability resides in '/web/admin/welcome.php' within the Admin Interface component. Attackers can remotely exploit this by manipulating the 'addnews' argument. Public exploit code is available for this vulnerability.

## Impact
Successful exploitation allows for unauthorized manipulation of administrative functions, specifically regarding the addition of content within the CMS, potentially leading to unauthorized data entry or administrative control depending on the context of the affected function.

## Recommendation
- Inventory all instances of code-projects Simple Content Management System in the environment.
- Prioritize restricting access to the '/web/admin/' directory via web server configuration to trusted management IPs.
- Monitor web server access logs for anomalous POST or GET requests targeting '/web/admin/welcome.php' containing the 'addnews' parameter.
