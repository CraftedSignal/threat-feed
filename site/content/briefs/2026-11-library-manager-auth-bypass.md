---
brief_id: brief-2026-11-09-library-manager-auth-bypass
event_id: brief-2026-11-09-library-manager-auth-bypass
revision: 1
activity_at: "2026-11-09T11:38:44Z"
title: 'zhangbw409 library_manager_system: Improper authorization via BookController (CVE-2026-124590)'
slug: 2026-11-library-manager-auth-bypass
description: A remote improper authorization vulnerability in zhangbw409 library_manager_system allows attackers to manipulate user-related parameters within the BookController.addBook method to bypass authorization.
date: "2026-11-09T11:38:44Z"
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
  validation_status: Analysis performed based on NVD disclosure.
cpes:
  - cpe:2.3:a:zhangbw409:library_manager_system:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - web-application
  - java
vendors:
  - zhangbw409
products:
  - library_manager_system (rolling release)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-124590
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124590
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify and isolate instances of library_manager_system from public-facing segments.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remotely exploitable and publicly disclosed.
  hunt_leads:
    - lead: Identify suspicious POST requests to the addBook method with anomalous parameter values
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves manipulation of userName, userPwd, userEmail, or userId in BookController.addBook.
  mitigation_plan:
    - priority: immediate
      action: Apply network access control lists (ACLs) to block untrusted traffic to library_manager_system endpoints
      owner: IT Operations
      addresses: CVE-2026-124590
      evidence: No vendor patch currently available for this rolling-release project.
---

A vulnerability exists in the library_manager_system project (commit hash f6c9d9c96bf5d2a32ef741daeaa29d80e6db166b) within the BookController.addBook function located in src/main/java/com/zbw/controller/UserController.java. Attackers can remotely exploit this by manipulating the userName, userPwd, userEmail, or userId parameters to perform unauthorized actions. The maintainers have not yet provided a patch for this rolling-release project.

## Impact
Successful exploitation allows remote attackers to bypass authorization controls, potentially leading to unauthorized data modification or administrative access depending on the context of the affected system.

## Recommendation
- Audit all deployments of the library_manager_system for exposed instances.
- Implement network-level restrictions to limit remote access to the BookController API endpoints.
- Monitor application logs for anomalous POST requests to the addBook method containing unusual characters or unexpected values in user parameter fields.
