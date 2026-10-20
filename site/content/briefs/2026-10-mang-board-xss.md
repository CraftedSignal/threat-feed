---
brief_id: brief-2026-10-15-mang-board-xss
event_id: brief-2026-10-15-mang-board-xss
revision: 1
activity_at: "2026-10-15T06:35:56Z"
title: Stored Cross-Site Scripting in Mang Board WP Plugin
slug: 2026-10-mang-board-xss
description: The Mang Board WP plugin for WordPress through version 2.4.0 is vulnerable to stored cross-site scripting (XSS) via the 'data_type' parameter, allowing unauthenticated attackers to execute arbitrary scripts in victim browsers.
date: "2026-10-15T06:35:56Z"
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
  - cpe:2.3:a:mang_board:mang_board:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - xss
  - wordpress
vendors:
  - Mang Board
products:
  - Mang Board WP plugin (<= 2.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Mang Board WP plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'data_type' parameter in all versions up to, and including, 2.4.0.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-88043
    cvss: 7.2
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88043
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Mang Board WP plugin to the latest version beyond 2.4.0
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability exists in versions up to and including 2.4.0.
  mitigation_plan:
    - priority: immediate
      action: Disable the Mang Board WP plugin if no patch is available.
      owner: IT Operations
      addresses: CVE-2026-88043
      evidence: Vulnerability allows unauthenticated script injection.
---

The Mang Board WP plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'data_type' parameter in all versions up to and including 2.4.0. The vulnerability stems from insufficient input sanitization and output escaping of user-supplied data. An unauthenticated attacker can inject arbitrary web scripts into the application, which are then stored by the server. When an unsuspecting user, such as an administrator, views the affected page, the malicious script executes within the context of the user's session. This flaw could lead to session hijacking, unauthorized administrative actions, or the redirection of users to malicious websites.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in the browser of any user viewing the compromised page. This can result in complete account takeover if an administrator views the injected content, leading to a full compromise of the WordPress installation and its associated database.

## Recommendation

Update the Mang Board WP plugin to a version released after 2.4.0 that incorporates proper input sanitization and output escaping for the 'data_type' parameter. If an update is unavailable, disable the plugin until a vendor patch is applied.
