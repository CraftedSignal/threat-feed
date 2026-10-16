---
title: Stored XSS in Colibri Page Builder Plugin for WordPress
slug: 2026-10-colibri-xss
description: An unauthenticated stored XSS vulnerability in the Colibri Page Builder plugin for WordPress allows attackers to inject malicious scripts via the comment parameter that execute in the context of user browsers.
date: "2026-10-16T04:24:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:colibriwp:colibri_page_builder:*:*:*:*:*:wordpress:*:*
vendors:
  - Colibri WP
products:
  - Colibri Page Builder (<= 1.0.390)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The resulting string directly into jQuery(), which parses a leading '<' as HTML and fires the embedded event handler.
    confidence_band: high
cves:
  - id: CVE-2026-107758
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107758
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Colibri Page Builder to a version > 1.0.390
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107758 vulnerability in versions 1.0.390 and lower
  mitigation_plan:
    - priority: immediate
      action: Upgrade Colibri Page Builder
      owner: IT Operations
      addresses: CVE-2026-107758
      evidence: Source identified the vulnerability in versions 1.0.390 and lower
---

The Colibri Page Builder plugin for WordPress (versions 1.0.390 and earlier) contains a critical stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-107758. The flaw stems from insufficient input sanitization and output escaping within the plugin's comment-handling logic. Attackers can submit crafted comments containing SVG elements with malicious data-* attributes, which are improperly permitted by the plugin's sanitization allow-list.

The vulnerability is triggered because the plugin's front-end script, colibri.js, is enqueued globally. This script retrieves the stored malicious data-target value using jQuery.data(). Because jQuery.data() automatically performs HTML-entity decoding on retrieved attributes, the decoded malicious payload is subsequently passed to the jQuery() constructor. When the constructor identifies a leading '<' character, it interprets the payload as HTML, causing any embedded event handlers (such as 'onerror') to execute in the browser of any user viewing the injected page. This impact is significant as it allows unauthenticated attackers to execute arbitrary JavaScript, potentially leading to session hijacking or unauthorized administrative actions.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in the context of any user viewing an affected page, including site administrators. This can lead to full site compromise through administrative account takeover, unauthorized data modification, or the redirection of users to malicious third-party content.

## Recommendation

* Immediately upgrade Colibri Page Builder to a version beyond 1.0.390 that incorporates proper input sanitization and output escaping.
* Audit WordPress comment logs for entries containing SVG tags or unexpected 'data-' attributes if the plugin remains temporarily active.
* Deploy web application firewall (WAF) rules to detect and block incoming HTTP POST requests containing suspicious SVG tag structures or dangerous HTML event handlers targeted at WordPress comment endpoints.
