---
brief_id: brief-2026-10-27-advanced-views-xss
event_id: brief-2026-10-27-advanced-views-xss
revision: 1
activity_at: "2026-10-27T13:49:08Z"
title: 'Advanced Views: Stored Cross-Site Scripting in Display Framework (CVE-2026-109995)'
slug: 2026-10-advanced-views-xss
description: The Advanced Views - Display Framework for Gutenberg & Elementor plugin for WordPress is vulnerable to unauthenticated Stored Cross-Site Scripting via the comment parameter, allowing arbitrary script execution on pages containing affected layout blocks.
date: "2026-10-27T13:49:08Z"
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
  validation_status: Source-verified vulnerability details
cpes:
  - cpe:2.3:a:advanced_views:display_framework_for_gutenberg_&_elementor:*:*:*:*:*:*:*:*
vendors:
  - Advanced Views
products:
  - Advanced Views – Display Framework for Gutenberg & Elementor (<= 3.9.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-109995
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109995
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Advanced Views - Display Framework for Gutenberg & Elementor to a patched version beyond 3.9.6.
      owner: IT Operations
      due: 48h
      evidence: Plugin is vulnerable up to and including 3.9.6.
  hunt_leads:
    - lead: Identify incoming POST requests to comment submission endpoints containing script tags or event handlers.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated attackers inject arbitrary web scripts via the comment parameter.
  mitigation_plan:
    - priority: immediate
      action: Apply security patch for CVE-2026-109995.
      owner: IT Operations
      addresses: CVE-2026-109995
      evidence: NVD identifies vulnerability in versions <= 3.9.6.
---

The Advanced Views - Display Framework for Gutenberg & Elementor plugin for WordPress (all versions up to and including 3.9.6) contains a Stored Cross-Site Scripting (XSS) vulnerability. Insufficient input sanitization and output escaping on the 'comment' parameter allow unauthenticated attackers to inject malicious web scripts.

The vulnerability is accessible because the plugin's `get_comment()` function does not filter for comment approval status. Consequently, an attacker can submit a malicious script in a pending or unapproved comment, which will then execute when any visitor loads a page containing an `avf-layout` block associated with the attacker's comment ID, bypassing the need for administrative approval.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browsers of users visiting pages with affected layout blocks. This can lead to session hijacking, unauthorized actions performed on behalf of authenticated users, or redirection to malicious content.

## Recommendation

* Update the "Advanced Views - Display Framework for Gutenberg & Elementor" plugin to a version released after 3.9.6 that addresses the sanitization and validation failures in the `comment` parameter.
* Monitor WordPress web server logs for suspicious POST requests targeting the comment submission endpoint that contain script tags or character sequences common in XSS payloads (e.g., `<script>`, `onerror`, `onload`).
* Review existing and pending comments for malicious scripts if the plugin remains unpatched in the environment.
