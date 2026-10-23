---
brief_id: brief-2026-10-23-aivahthemes-hostme-xss
event_id: brief-2026-10-23-aivahthemes-hostme-xss
revision: 1
activity_at: "2026-10-23T13:41:06Z"
title: 'AivahThemes Hostme: DOM-based cross-site scripting (CVE-2026-112849)'
slug: 2026-10-aivahthemes-hostme-xss
description: AivahThemes Hostme version 7.0 and earlier contains a DOM-based cross-site scripting vulnerability resulting from improper input sanitization during web page generation.
date: "2026-10-23T13:41:06Z"
lastmod: "2026-10-23T15:07:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:aivahthemes:hostme:*:*:*:*:*:*:*:*
  - cpe:2.3:a:aivahthemes:hostme_v2:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - vulnerability
vendors:
  - AivahThemes
products:
  - Hostme v2 (n/a through 7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in AivahThemes Hostme v2 hostmev2 allows DOM-Based XSS.
    confidence_band: high
cves:
  - id: CVE-2026-112849
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-112848
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112849
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112848
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all servers running AivahThemes Hostme v2
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112849 affected version range
  hunt_leads:
    - lead: Search web application logs for unusual URL parameters containing script tags or JavaScript event handlers
      technique_id: T1059.007
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is DOM-based XSS allowing script execution
  mitigation_plan:
    - priority: immediate
      action: Deploy Content Security Policy (CSP) to restrict allowed script sources
      owner: IT Operations
      addresses: CVE-2026-112849
      evidence: Mitigation for DOM-based XSS
updates:
  - at: "2026-10-23T15:07:25Z"
    level: L3
    summary: severity → critical; added CVE-2026-112848
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112848
---

A vulnerability identified as CVE-2026-112849 exists in AivahThemes Hostme v2 (versions up to 7.0). The software fails to properly neutralize user-controlled input, leading to DOM-based Cross-Site Scripting (XSS). This vulnerability allows an attacker to inject and execute arbitrary scripts within the context of a victim's browser session when they interact with a crafted page. No patch availability is currently noted in the source.

## Impact
Successful exploitation allows for the execution of malicious scripts in the victim's browser, potentially leading to session hijacking, unauthorized actions performed on behalf of the user, or redirection to malicious sites.

## Recommendation
- Inventory all instances of AivahThemes Hostme v2 within the environment.
- Apply strict input validation and output encoding for all user-controllable data on web-facing applications.
- Monitor web traffic and user sessions for suspicious script execution or unexpected redirections emanating from the Hostme application.
- Implement a strong Content Security Policy (CSP) to mitigate the impact of potential XSS attacks.
