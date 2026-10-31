---
brief_id: brief-2026-10-31-ppwp-xss
event_id: brief-2026-10-31-ppwp-xss
revision: 1
activity_at: "2026-10-31T07:51:36Z"
title: 'Password Protect WordPress: Stored Cross-Site Scripting (CVE-2026-116520)'
slug: 2026-10-ppwp-xss
description: The PPWP Password Protect Pages plugin for WordPress is vulnerable to unauthenticated Stored Cross-Site Scripting via improper input sanitization in shortcode attributes, allowing script injection into pages.
date: "2026-10-31T07:51:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation verified
cpes:
  - cpe:2.3:a:password_protect_wordpress:password_protect_pages:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
  - cve-2026-116520
vendors:
  - Password Protect WordPress
products:
  - PPWP – Password Protect Pages (<= 1.9.26)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is exploitable by unauthenticated attackers because WordPress's comment_content filter leaves bare shortcode text (containing no HTML tags) untouched.
    confidence_band: high
cves:
  - id: CVE-2026-116520
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116520
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update PPWP - Password Protect Pages to the latest version to address CVE-2026-116520
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to and including 1.9.26 are vulnerable
  hunt_leads:
    - lead: Search web access logs for POST requests to WordPress pages that contain script tags or suspicious JavaScript attributes (e.g., onerror, onclick) in the query parameters or request body associated with form interactions
      technique_id: T1190
      data_needed:
        - Web server access logs (e.g., Apache/Nginx logs)
        - WAF logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
  mitigation_plan:
    - priority: immediate
      action: Disable 'comment_whitelist' in WordPress settings to prevent auto-approval of malicious content
      owner: IT Operations
      addresses: CVE-2026-116520
      evidence: comment_whitelist setting auto-approves subsequent comments from a previously approved name and email without administrator intervention
---

The PPWP - Password Protect Pages plugin for WordPress (versions up to and including 1.9.26) contains a Stored Cross-Site Scripting vulnerability. Insufficient input sanitization and output escaping of the 'desc_below_form' and 'placeholder' attributes allow unauthenticated attackers to inject arbitrary web scripts into WordPress pages. The vulnerability is further enabled by the plugin's comment filtering logic, which ignores bare shortcode text, and the 'comment_whitelist' setting, which can auto-approve comments from previously approved authors.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of the WordPress site when a victim views an injected page. This may lead to session hijacking, unauthorized actions performed on behalf of administrators, or further redirection of users to malicious sites.

## Recommendation
- Update the PPWP - Password Protect Pages plugin to the version following 1.9.26 (or the latest available patch) as soon as it becomes available.
- Review the 'comment_whitelist' configuration in the WordPress administrative panel and disable it if not strictly required to mitigate the persistence of unauthenticated malicious comments.
- Implement a Content Security Policy (CSP) to restrict the execution of unauthorized inline scripts on the WordPress installation.
- Hunt for web requests containing malicious script tags or JavaScript event handlers (e.g., onerror, onload, onclick) directed at pages utilizing the vulnerable shortcodes.
