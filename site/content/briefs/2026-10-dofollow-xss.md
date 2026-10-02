---
title: Stored XSS in DoFollow Case by Case WordPress Plugin
slug: 2026-10-dofollow-xss
description: The DoFollow Case by Case plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization, allowing unauthenticated attackers to execute arbitrary scripts in the browsers of site visitors.
date: "2026-10-02T08:24:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:dofollow_case_by_case:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - WordPress
products:
  - DoFollow Case by Case (<= 3.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: This allows for potential session hijacking or unauthorized actions performed on behalf of authenticated users.
    confidence_band: high
cves:
  - id: CVE-2026-95817
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95817
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update DoFollow Case by Case plugin to version > 3.6.0
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to 3.6.0
  mitigation_plan:
    - priority: immediate
      action: Disable comment functionality for affected WordPress posts
      owner: IT Operations
      addresses: CVE-2026-95817
      evidence: Comment moderation delays but does not prevent exploitation
---

The DoFollow Case by Case plugin for WordPress (all versions up to and including 3.6.0) contains a vulnerability that permits Stored Cross-Site Scripting (XSS). This flaw stems from the plugin's failure to properly sanitize and escape content submitted via comment fields. Because the input is not validated, an unauthenticated attacker can embed malicious JavaScript payloads within a comment submission. 

While standard WordPress comment moderation settings may delay the delivery of the exploit, once an administrator approves a comment containing a payload, the script is rendered on the post page. Subsequently, the script executes within the context of any user's browser who views the affected post, including site administrators. This vulnerability poses a significant risk to the integrity of the WordPress site by enabling session hijacking, account takeover, or unauthorized administrative actions. Defenders should treat this as a high-priority risk if the plugin cannot be immediately updated or removed.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browsers of site visitors, including high-privileged administrators. This can lead to the theft of session cookies, the creation of rogue administrator accounts, or unauthorized content modification, effectively compromising the WordPress site and its user base.

## Recommendation

* Update the DoFollow Case by Case plugin to a patched version beyond 3.6.0 immediately.
* Disable the comment feature on public-facing posts until the patch is verified and applied.
* Monitor web server logs for suspicious HTTP POST requests directed at comment submission endpoints (`/wp-comments-post.php`) containing script tags or common XSS vectors.
