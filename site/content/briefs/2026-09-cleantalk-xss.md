---
title: Stored XSS in CleanTalk WordPress Plugin
slug: 2026-09-cleantalk-xss
description: The Spam protection, Honeypot, Anti-Spam by CleanTalk plugin for WordPress is vulnerable to stored cross-site scripting via insufficient input sanitization in the comment content aria-label placeholder, allowing attackers to execute arbitrary scripts in the browsers of site visitors.
date: "2026-09-05T07:30:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cleantalk:spam_protection_honeypot_anti_spam_by_cleantalk:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - CleanTalk
products:
  - Spam protection, Honeypot, Anti-Spam by CleanTalk (<= 6.86)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Spam protection, Honeypot, Anti-Spam by CleanTalk plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content aria-label Placeholder
    confidence_band: high
cves:
  - id: CVE-2026-77830
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77830
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CleanTalk plugin to version 6.87 or higher
      owner: IT Operations
      due: 48h
      evidence: Source identifies CVE-2026-77830 in versions up to 6.86
  mitigation_plan:
    - priority: immediate
      action: Review and patch plugin
      owner: IT Operations
      addresses: CVE-2026-77830
      evidence: NVD vulnerability disclosure
---

The Spam protection, Honeypot, Anti-Spam by CleanTalk plugin for WordPress is vulnerable to stored cross-site scripting (XSS) in all versions up to and including 6.86. The vulnerability stems from insufficient sanitization of input data when processing the comment content aria-label placeholder. Authenticated attackers with custom-level access or higher can inject arbitrary JavaScript payloads through comment submissions. If comment moderation is enabled on the WordPress installation, the payload remains dormant until a site administrator approves the comment. Once published, the malicious script executes within the browser context of any non-logged-in visitor who views the page containing the comment. This vulnerability represents a significant risk for site integrity, potentially allowing for session hijacking, malicious redirects, or unauthorized actions performed on behalf of the victim.

## Impact

Successful exploitation results in arbitrary code execution within the context of site visitors' browsers. This can lead to the theft of session cookies, redirection to malicious phishing sites, or unauthorized modifications to the page content viewed by the end-user. The target audience for the malicious script is primarily non-authenticated visitors, though the scope of impact depends on the traffic volume and the visibility of the compromised comment section on the affected WordPress site.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

- Update the "Spam protection, Honeypot, Anti-Spam by CleanTalk" plugin to version 6.87 or the latest available release to resolve the sanitization flaw identified in CVE-2026-77830.
- Review web access logs for suspicious HTTP POST requests directed at the WordPress comment submission endpoint (typically /wp-comments-post.php) that contain script tags or suspicious JavaScript event handlers in the comment metadata.
- Enforce strict content security policies (CSP) on WordPress deployments to mitigate the execution of unauthorized inline scripts.
- Audit user roles and permissions to ensure that only trusted users possess custom-level or higher access to the WordPress environment.
