---
title: Stored Cross-Site Scripting in WP Meteor Website Speed Optimization Addon
slug: 2026-10-wp-meteor-xss
description: The WP Meteor Website Speed Optimization Addon for WordPress versions 3.4.18 and earlier contains a Stored XSS vulnerability allowing unauthenticated attackers to inject malicious scripts via the comment author name field.
date: "2026-10-10T07:53:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpmeteor:wp_meteor_website_speed_optimization_addon:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
  - cve-2026-96572
vendors:
  - WP Meteor
products:
  - WP Meteor Website Speed Optimization Addon (<= 3.4.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96572
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96572
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update plugin to latest version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-96572 advisory
  mitigation_plan:
    - priority: immediate
      action: Enable WAF protections for comment injection
      owner: SOC
      addresses: CVE-2026-96572
      evidence: Stored XSS in comment author field
---

The WP Meteor Website Speed Optimization Addon plugin for WordPress contains a Stored Cross-Site Scripting (XSS) vulnerability impacting all versions up to and including 3.4.18. The flaw arises from insufficient input sanitization and output escaping within the comment author name field. An unauthenticated attacker can supply a crafted payload containing malicious JavaScript as the comment author name. While the comment must bypass the site's moderation workflow to be displayed, the application fails to safely process the input, resulting in the script executing in the browser of any user who views the page where the comment is rendered. This vulnerability presents a high risk for account takeover, session hijacking, or site redirection when administrators or authenticated users interact with the infected comments section.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of the victim's browser session. Depending on the privileges of the user viewing the compromised page, this can lead to administrative account takeover, unauthorized modification of site content, or the injection of further malicious redirects and phishing content. The impact is significant for site integrity and user security, as it affects the frontend display of comments across the WordPress installation.

## Recommendation

Prioritized actions for security and IT teams:
- Update the WP Meteor Website Speed Optimization Addon to a version beyond 3.4.18 as soon as a patch is available.
- Implement a Content Security Policy (CSP) that restricts script execution to trusted domains to mitigate the impact of stored XSS.
- Utilize Web Application Firewall (WAF) rules to inspect comment submissions for common JavaScript injection patterns (e.g., &lt;script>, onload, onerror).
- Review all existing pending comments for suspicious author names if the site allows unauthenticated posting.
