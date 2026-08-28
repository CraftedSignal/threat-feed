---
title: Stored XSS in LiteSpeed Cache for WordPress via Comment Content
slug: 2026-08-litespeed-xss
description: An unauthenticated stored XSS vulnerability in LiteSpeed Cache versions 7.8.1 and below allows attackers to inject malicious scripts into WordPress comments by bypassing wp_kses input sanitization.
date: "2026-08-28T07:11:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - LiteSpeed Technologies
products:
  - LiteSpeed Cache (<= 7.8.1)
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
    evidence: allows malicious payloads to reach the vulnerable function.
    confidence_band: high
cves:
  - id: CVE-2026-18978
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18978
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch LiteSpeed Cache plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18978 remediation
  mitigation_plan:
    - priority: immediate
      action: Enable 'require_name_email' setting in WordPress discussion settings
      owner: IT Operations
      addresses: CVE-2026-18978 prerequisite
      evidence: Source states requirement for exploitation
---

LiteSpeed Cache for WordPress, in versions up to and including 7.8.1, contains a high-severity Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-18978). The flaw resides in the plugin's insufficient sanitization and output escaping of user-supplied comment content. Specifically, attackers can bypass the WordPress `wp_kses` sanitization function by crafting payloads using decimal numeric character references (e.g., HTML entities for quotes, brackets) placed inside allowed HTML elements like `<code>`. 

Because `wp_kses` fails to recognize certain patterns as dangerous HTML attributes when nested within allowed elements, malicious scripts can persist in the comment database. These scripts execute in the context of the browser for any user (including administrators) who visits the page containing the injected comment. Successful exploitation requires a specific configuration where the WordPress site allows comments from previously approved users and has the "require_name_email" setting disabled.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browsers of site visitors or administrators. This can lead to session hijacking, unauthorized actions performed on behalf of the victim (such as creating new administrative users or modifying site content), and credential theft. The impact is significant for high-traffic WordPress sites that allow user comments, particularly if site administrators frequently visit comment-heavy pages.

## Recommendation

* Update the LiteSpeed Cache plugin to the latest version immediately to remediate CVE-2026-18978.
* Audit WordPress site settings to enable "require_name_email" for comments to increase the friction for unauthenticated attackers.
* Review site comment moderation settings to ensure new comments from previously approved authors are held for review if the plugin update cannot be applied immediately.
* Monitor web server logs for suspicious HTTP POST requests to the WordPress comment submission endpoint (`/wp-comments-post.php`) containing HTML numeric entities or script-like patterns.
