---
brief_id: brief-2026-10-21-jane-menu-xss
event_id: brief-2026-10-21-jane-menu-xss
revision: 1
activity_at: "2026-10-21T11:19:25Z"
title: 'Jane Menu WordPress Plugin: Unauthenticated Stored Cross-Site Scripting (CVE-2026-85683)'
slug: 2026-10-jane-menu-xss
description: The Jane Menu WordPress plugin prior to 1.5.1 contains a vulnerability allowing unauthenticated attackers to perform Stored Cross-Site Scripting via improper capability and nonce checks in a form handler.
date: "2026-10-21T11:19:25Z"
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
  validation_status: verified against NVD vulnerability metadata
cpes:
  - cpe:2.3:a:jane_menu:jane_menu:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-vulnerability
vendors:
  - Jane Menu
products:
  - Jane Menu (< 1.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Jane Menu WordPress plugin before 1.5.1 does not have any capability or nonce checks on one of its form handlers, which is reachable by unauthenticated users
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: an unauthenticated attacker can run arbitrary JavaScript in the browser of any visitor to that page
    confidence_band: high
cves:
  - id: CVE-2026-85683
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85683
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Jane Menu plugin to version 1.5.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85683 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade Jane Menu plugin to 1.5.1
      owner: IT Operations
      addresses: CVE-2026-85683
      evidence: Vendor patch release for CVE-2026-85683
---

The Jane Menu plugin for WordPress versions prior to 1.5.1 fails to implement capability or nonce checks on a specific form handler. This flaw allows unauthenticated remote attackers to bind existing published pages to arbitrary external documents. When the plugin fetches and displays the content of these remote documents, it fails to sanitize or escape the output, resulting in Stored Cross-Site Scripting (XSS). This enables the execution of arbitrary JavaScript in the browser context of any visitor to the affected page, including authenticated administrators.

## Impact

Successful exploitation leads to unauthorized JavaScript execution within the visitor's browser session. This can be used to perform actions on behalf of the user, steal session cookies, or facilitate further administrative compromise if an administrator visits the affected page.

## Recommendation

* Update the Jane Menu plugin to version 1.5.1 or later immediately.
* Monitor WordPress web server logs for suspicious POST requests to the plugin's form handling endpoints, particularly those originating from unauthenticated sessions.
* Audit existing published pages on WordPress sites using this plugin to identify unauthorized document bindings.
