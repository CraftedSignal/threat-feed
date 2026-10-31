---
brief_id: brief-2026-10-31-thelia-csrf
event_id: brief-2026-10-31-thelia-csrf
revision: 1
activity_at: "2026-10-31T20:04:52Z"
title: 'Thelia Page Module: Cross-Site Request Forgery (CVE-2026-120207)'
slug: 2026-10-thelia-csrf
description: The Thelia Page Module before 2.0.4 is vulnerable to CSRF, allowing an attacker to trick a logged-in administrator into triggering unauthorized deletions of tags, documents, and images.
date: "2026-10-31T20:04:52Z"
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
  validation_status: Source verified; no environment validation performed.
cpes:
  - cpe:2.3:a:thelia:page_module:*:*:*:*:*:*:*:*
vendors:
  - Thelia
products:
  - Page Module (< 2.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can lure a logged-in administrator into navigating to crafted GET requests
    confidence_band: high
cves:
  - id: CVE-2026-120207
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120207
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Thelia Page Module to version 2.0.4 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-120207 vulnerability disclosure
  hunt_leads:
    - lead: Identify suspicious back-office GET requests containing sequential ID parameters targeting deletion routes
      technique_id: T1521
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can lure a logged-in administrator into navigating to crafted GET requests that walk sequential ids
  mitigation_plan:
    - priority: immediate
      action: Upgrade Page Module to 2.0.4
      owner: IT Operations
      addresses: CVE-2026-120207
      evidence: Thelia Page Module before 2.0.4 contains a cross-site request forgery vulnerability
---

Thelia Page Module versions prior to 2.0.4 contain a cross-site request forgery (CSRF) vulnerability in back-office delete routes. The vulnerability stems from a lack of CSRF tokens and insufficient permission checks, allowing an attacker to craft malicious GET requests that, when visited by a logged-in administrator, result in the deletion of site content. Attackers can leverage this to delete page tags, documents, and TheliaLibrary assets by iterating through sequential IDs.

## Impact

Successful exploitation allows for the unauthorized deletion of site images, documents, and page tags across pages, products, and categories. This can result in significant loss of site content and broken site functionality.

## Recommendation

1. Upgrade the Thelia Page Module to version 2.0.4 or later immediately.
2. Implement administrative session monitoring to identify anomalous administrative activity following periods of suspected phishing or social engineering.
3. Ensure that administrative access to the Thelia back-office is restricted to trusted networks and protected by robust authentication controls to minimize exposure to CSRF triggers.
