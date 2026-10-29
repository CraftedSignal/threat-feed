---
brief_id: brief-2026-10-29-codeastro-xss
event_id: brief-2026-10-29-codeastro-xss
revision: 1
activity_at: "2026-10-29T07:59:32Z"
title: 'Codeastro Internet Banking System: Stored Cross-Site Scripting (CVE-2025-29018)'
slug: 2026-10-codeastro-xss
description: Codeastro Internet Banking System 2.0.0 contains a stored XSS vulnerability in the pages_add_acc_type.php component that allows authenticated attackers to inject malicious JavaScript, potentially leading to session hijacking.
date: "2026-10-29T07:59:32Z"
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
  validation_status: Rule defined based on published PoC payload structure
cpes:
  - cpe:2.3:a:codeastro:internet_banking_system:2.0.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - injection
vendors:
  - Codeastro
products:
  - Internet Banking System (2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Stored Cross-Site Scripting (XSS) vulnerability exists in Code Astro Internet Banking System 2.0.0 due to unsanitized input in the name parameter
    confidence_band: high
cves:
  - id: CVE-2025-29018
    cvss: 4.8
    epss: 0.00272
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-B1TM4R-CVE-2025-29018
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-B1TM4R-CVE-2025-29018&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2025-29018 Exploitation - Stored XSS in Internet Banking System
    description: Detects attempted injection of script tags into the name parameter of pages_add_acc_type.php
    platform: sigma
    severity: medium
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
    - action: Deploy Sigma rule for webserver log monitoring
      owner: Detection Engineering
      due: 24h
      evidence: Source document confirms XSS via name parameter in pages_add_acc_type.php
  hunt_leads:
    - lead: Search for existing script tags stored in the application database
      technique_id: T1190
      data_needed:
        - Backend database or application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Stored XSS allows persistent malicious JavaScript execution
  mitigation_plan:
    - priority: immediate
      action: Sanitize user input and implement CSP
      owner: IT Operations
      addresses: Codeastro Internet Banking System 2.0.0
      evidence: Mitigation section of source disclosure
---

Codeastro Internet Banking System 2.0.0 is vulnerable to a stored cross-site scripting (XSS) attack via the 'name' parameter in 'pages_add_acc_type.php'. The vulnerability allows an authenticated attacker with high-level privileges to inject arbitrary JavaScript, which executes when an administrator or user views the 'Manage Acc Types' administrative page. 

## Attack Chain
1. Attacker authenticates to the application with privileges sufficient to add account types.
2. Attacker navigates to the "Add Acc Type" functionality.
3. Attacker submits a malicious payload containing JavaScript within the 'name' parameter field.
4. The application saves the unsanitized payload into the backend database.
5. An administrator or user accesses the "Manage Acc Types" administrative menu.
6. The application renders the stored payload within the admin interface, triggering JavaScript execution in the victim's browser session.

## Impact
Successful exploitation allows for the execution of arbitrary JavaScript in the context of the victim's browser session. Documented potential impacts include session hijacking, credential theft, and unauthorized account takeover.

## Recommendation
- Identify and inventory all instances of Codeastro Internet Banking System 2.0.0 within the environment.
- Implement strict HTML entity encoding for all user-supplied input fields, specifically the 'name' parameter in 'pages_add_acc_type.php'.
- Deploy a robust Content Security Policy (CSP) to restrict the execution of unauthorized inline scripts.
- Until a patch is provided, restrict access to administrative functions and audit logs for anomalous changes to account type definitions.
