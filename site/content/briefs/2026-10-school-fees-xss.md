---
brief_id: brief-2026-10-27-school-fees-xss
event_id: brief-2026-10-27-school-fees-xss
revision: 1
activity_at: "2026-10-27T04:13:38Z"
title: 'oretnom23 School Fees Management System: Stored XSS in tname parameter (CVE-2023-49987)'
slug: 2026-10-school-fees-xss
description: The School Fees Management System version 1.0 is vulnerable to stored cross-site scripting (XSS) via the tname parameter in the new_term administrative component.
date: "2026-10-27T04:13:38Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment verification
cpes:
  - cpe:2.3:a:oretnom23:school_fees_management_system:1.0:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - oretnom23
products:
  - School Fees Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: A cross-site scripting (XSS) vulnerability exists in the /management/term component where the tname parameter is not properly sanitized, allowing for the execution of arbitrary web scripts.
    confidence_band: high
cves:
  - id: CVE-2023-49987
    cvss: 5.4
    epss: 0.00431
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GERALDOALCANTARA-CVE-2023-49987
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GERALDOALCANTARA-CVE-2023-49987&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2023-49987 XSS Attempt in Web Logs
    description: Detects attempts to inject script tags into the tname parameter of the term management endpoint
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory instances of School Fees Management System 1.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerable software version identification
  hunt_leads:
    - lead: Search web server logs for HTTP requests to /management/term containing script tags
      technique_id: T1059.007
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Reported XSS vector in the tname parameter
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to drop POST requests to /management/term containing script-like content
      owner: IT Operations
      addresses: CVE-2023-49987
      evidence: Reported XSS vulnerability
  gaps:
    - No official vendor patch identified for version 1.0
---

A stored cross-site scripting (XSS) vulnerability exists in the School Fees Management System version 1.0. An authenticated attacker with administrative access can inject arbitrary web scripts through the tname parameter within the /management/term component. Successful exploitation requires an authenticated user with administrative privileges to interact with the vulnerable form to save the payload, which is subsequently executed in the context of the user viewing the term management page.

## Impact
Successful exploitation allows for the execution of arbitrary JavaScript in the victim's browser session, potentially leading to session hijacking, unauthorized actions performed on behalf of the administrator, or unauthorized access to sensitive system data managed by the application.

## Recommendation
- Audit logs for the specified endpoint (/management/term) to identify potential injection of script tags.
- Implement input validation and output encoding for the tname parameter within the School Fees Management System to prevent script injection.
- As version 1.0 appears to be the only version listed, evaluate the use of this software within the environment given the lack of identified security updates.
