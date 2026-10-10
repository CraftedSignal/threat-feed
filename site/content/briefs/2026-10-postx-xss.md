---
title: Stored XSS in Post Grid Gutenberg Blocks - PostX Plugin
slug: 2026-10-postx-xss
description: The Post Grid Gutenberg Blocks - PostX WordPress plugin (<= 5.1.0) is vulnerable to stored Cross-Site Scripting via the display_name field due to insufficient sanitization of double-quotes.
date: "2026-10-10T07:53:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpxpress:post_grid_gutenberg_blocks_–_postx:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Post Grid Gutenberg Blocks – PostX (<= 5.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96840
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96840
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review WordPress user profiles for malicious scripts in display_name fields
      owner: Security Operations
      due: 24h
      evidence: The display_name user field is the primary vector for this stored XSS.
  mitigation_plan:
    - priority: immediate
      action: Upgrade PostX plugin once a fix is released or disable the plugin if not critical
      owner: IT Operations
      addresses: CVE-2026-96840
      evidence: Source confirms vulnerability exists in version 5.1.0 and below.
---

The Post Grid Gutenberg Blocks - PostX plugin for WordPress, in all versions up to and including 5.1.0, contains a stored Cross-Site Scripting (XSS) vulnerability. The issue stems from insufficient input sanitization and output escaping within the display_name user field. While WordPress core applies partial encoding to characters like ampersands and brackets, it does not encode double-quotes (due to ENT_NOQUOTES usage). This oversight allows an attacker with Subscriber-level access to inject a payload containing double-quotes via the /wp-admin/profile.php endpoint. The malicious payload is subsequently rendered on the frontend in the Archive_Title.php file at line 144, where it breaks out of an HTML attribute, enabling the execution of arbitrary JavaScript when an unsuspecting user, such as an administrator, views the compromised page. This vulnerability poses a significant risk to site integrity and administrative session security.

## Impact

Successful exploitation allows unauthenticated or low-privileged attackers to execute arbitrary JavaScript in the context of the victim's session. This can lead to the theft of administrative session cookies, unauthorized administrative actions, or defacement of the website. The vulnerability affects all sites utilizing the affected versions of the PostX plugin.

## Recommendation

1. Upgrade the Post Grid Gutenberg Blocks - PostX plugin to a version beyond 5.1.0 as soon as a security update is released by the vendor.
2. Audit current WordPress user display names for suspicious characters, specifically double-quotes, to identify potential exploitation attempts.
3. Implement a strict Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities by restricting the execution of unauthorized scripts.
