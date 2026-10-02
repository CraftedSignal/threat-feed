---
title: Stored Cross-Site Scripting in W3 Total Cache
slug: 2026-10-w3-total-cache-xss
description: The W3 Total Cache plugin for WordPress contains a Stored Cross-Site Scripting (XSS) vulnerability, CVE-2026-87920, allowing unauthenticated attackers to execute arbitrary web scripts via flawed Output-Buffer Regex rewriting.
date: "2026-10-02T10:24:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:w3_edge:w3_total_cache:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application
  - wordpress
  - cve-2026-87920
vendors:
  - W3 EDGE
products:
  - W3 Total Cache (<= 2.10.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The W3 Total Cache plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content via Output-Buffer Regex Rewrite.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-87920
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87920
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade W3 Total Cache to version > 2.10.6
      owner: IT Operations
      due: 24h
      evidence: Source identified the vulnerability in versions up to and including 2.10.6.
  mitigation_plan:
    - priority: immediate
      action: Disable 'Remove query strings from static resources' in W3 Total Cache
      owner: IT Operations
      addresses: CVE-2026-87920
      evidence: Exploitation requires the Remove query strings from static resources option enabled.
---

The W3 Total Cache plugin for WordPress, in versions up to and including 2.10.6, is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-87920. The flaw resides within the Output-Buffer Regex Rewrite functionality, specifically the mutate_url() function. When the 'Remove query strings from static resources' configuration option is active, the plugin fails to perform sufficient input sanitization and output escaping. 

Attackers can leverage this by crafting malicious input that disrupts attribute boundaries. Specifically, the mutate_url() function improperly strips the '?' delimiter and subsequent characters, which can include the closing quote of an HTML attribute. By manipulating this regex logic, an unauthenticated attacker can escape the intended attribute context and inject arbitrary JavaScript. This payload is then stored and executed in the browsers of users who visit the affected pages. The vulnerability is critical for WordPress administrators and users because it enables session hijacking, unauthorized actions, or site-wide content modification.

## Impact

Successful exploitation allows unauthenticated attackers to inject arbitrary web scripts into WordPress pages. This could lead to the theft of administrative session cookies, redirection of users to malicious sites, or unauthorized modification of site content. Given the widespread use of W3 Total Cache, the potential attack surface is significant, affecting any WordPress installation where the specific 'Remove query strings from static resources' setting is enabled.

## Recommendation

1. Upgrade the W3 Total Cache plugin to the latest version immediately to remediate the flaw addressed in CVE-2026-87920.
2. Until patching is possible, disable the 'Remove query strings from static resources' setting in the W3 Total Cache plugin configuration to mitigate the exploitation vector.
3. Implement a robust Content Security Policy (CSP) to limit the impact of potential XSS attacks by restricting the sources from which scripts can be executed.
