---
brief_id: brief-2026-11-06-apache-axis2-xss
event_id: brief-2026-11-06-apache-axis2-xss
revision: 1
activity_at: "2026-11-06T19:23:09Z"
title: 'Apache Axis2/Java: Cross-site scripting in OpenAPI module (CVE-2026-123766)'
slug: 2026-11-apache-axis2-xss
description: Apache Axis2/Java version 2.0.1 contains a cross-site scripting (XSS) vulnerability in its OpenAPI module caused by improper sanitization of the Host header.
date: "2026-11-06T19:23:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:apache:axis2:2.0.1:*:*:*:*:java:*:*
vendors:
  - Apache
products:
  - Axis2/Java (< 2.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: The Swagger UI page served by the OpenAPI module wrote a value derived from the request Host header into the page without encoding, allowing script injection in the context of the Axis2 origin.
    confidence_band: high
cves:
  - id: CVE-2026-123766
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/558
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Apache Axis2/Java to 2.0.2 or higher
      owner: IT Operations
      due: 72h
      evidence: Source notes version 2.0.1 is vulnerable and 2.0.2 contains the fix.
  hunt_leads:
    - lead: Hunt for HTTP requests with unusual, non-standard, or script-heavy strings in the Host header targeting the Swagger UI endpoint
      technique_id: T1189
      data_needed:
        - Web server access logs
        - WAF logs (Host header field)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability is specifically caused by reflection of the Host header.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Reverse Proxy to sanitize or restrict the Host header
      owner: IT Operations
      addresses: CVE-2026-123766
      evidence: The vulnerability is triggered via the Host header reflection.
---

Apache Axis2/Java versions prior to 2.0.2 are vulnerable to cross-site scripting (XSS) within the OpenAPI module. The vulnerability occurs because the Swagger UI page improperly handles the Host header, injecting it into the web page content without sanitization. This allows remote attackers to execute arbitrary scripts in the context of the Axis2 origin.

## Impact

Successful exploitation allows remote attackers to execute arbitrary scripts in the context of the Axis2 origin, potentially leading to session hijacking or unauthorized actions performed by users viewing the affected Swagger UI page.

## Recommendation

* Update Apache Axis2/Java to version 2.0.2 or later to remediate the underlying XSS vulnerability in the OpenAPI module.
* As a temporary mitigation, utilize a web application firewall (WAF) to inspect and sanitize the Host header value in incoming requests before they reach the backend application.
