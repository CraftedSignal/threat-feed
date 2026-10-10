---
title: Stored XSS in LazyLoad Plugin for WordPress via Comment Injection
slug: 2026-10-lazyload-xss
description: The LazyLoad Plugin for WordPress up to version 2.4.0 is vulnerable to Stored Cross-Site Scripting (XSS) due to improper sanitization of the comment_content parameter, allowing attackers to inject malicious scripts that execute upon administrator approval.
date: "2026-10-10T07:52:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:lazyload_plugin_lazy_load_images_videos_and_iframes:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - WordPress
products:
  - LazyLoad Plugin – Lazy Load Images, Videos, and Iframes (<= 2.4.0)
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
    evidence: The event handler is concealed inside a broken attribute region and is only promoted to a real DOM attribute by the plugin's render-time str_replace transformation.
    confidence_band: high
cves:
  - id: CVE-2026-100196
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100196
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update LazyLoad Plugin to version 2.4.1 or later
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable in versions up to and including 2.4.0
  mitigation_plan:
    - priority: immediate
      action: Disable LazyLoad plugin if an update is not immediately available
      owner: IT Operations
      addresses: CVE-2026-100196
      evidence: Plugin contains stored XSS via comment_content parameter
---

The LazyLoad Plugin (version 2.4.0 and below) for WordPress contains a Stored Cross-Site Scripting (XSS) vulnerability. The vulnerability resides in how the plugin handles the 'comment_content' parameter during render-time. While WordPress core's 'wp_kses_data' function attempts to sanitize input, the plugin performs an additional 'str_replace' transformation on the content before output. This transformation promotes concealed event handlers within broken attribute regions into active, executable DOM attributes.

Because the script is injected via comment fields, an attacker must submit a comment containing the crafted payload. The vulnerability is only realized if a site administrator subsequently approves the comment, at which point the malicious payload is served to other users visiting the site. This allows unauthenticated attackers to execute arbitrary JavaScript in the context of other site visitors or administrative sessions.

## Attack Chain

1. Attacker crafts an HTTP POST request targeting a public-facing WordPress comment submission form.
2. The 'comment_content' parameter is populated with a payload containing concealed event handlers inside malformed HTML attributes to bypass 'wp_kses_data'.
3. The malicious comment is submitted to the target WordPress instance.
4. The WordPress site administrator reviews the pending comment queue.
5. The administrator approves the crafted comment, causing it to be committed to the site database.
6. The LazyLoad plugin processes the stored comment using its 'str_replace' transformation, converting the concealed handler into an active executable tag.
7. A legitimate user or administrator views the page containing the comment.
8. The injected script executes in the user's browser, enabling session hijacking or further client-side exploitation.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of any user who views the infected page. This can lead to account takeover, unauthorized administrative actions, or the theft of session cookies if an administrator views the comment. Given that this requires manual administrative approval, it serves as a persistent, high-impact vector for social engineering or site-wide malware distribution.

## Recommendation

Update the LazyLoad Plugin to a version beyond 2.4.0 immediately. If an update is unavailable, disable the plugin or restrict comment posting to authenticated users only. Review current comment queues for suspicious payloads containing malformed HTML attributes or unusual event handlers.
