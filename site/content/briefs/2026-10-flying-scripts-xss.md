---
title: Stored Cross-Site Scripting in Flying Scripts WordPress Plugin
slug: 2026-10-flying-scripts-xss
description: An unauthenticated stored XSS vulnerability in the Flying Scripts WordPress plugin (CVE-2026-109990) allows attackers to execute arbitrary JavaScript by bypassing core sanitization through an output-buffer rewriter.
date: "2026-10-16T04:24:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp-flying-scripts:flying_scripts:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-109990
products:
  - 'Flying Scripts: Delay JavaScript to Improve Site Speed & Performance (<= 1.2.4)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-109990
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109990
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Flying Scripts plugin to a patched version beyond 1.2.4
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends patching for CVE-2026-109990
  mitigation_plan:
    - priority: immediate
      action: Update to latest plugin version
      owner: IT Operations
      addresses: CVE-2026-109990
      evidence: NVD advisory confirms vulnerability in <= 1.2.4
---

The Flying Scripts: Delay JavaScript to Improve Site Speed & Performance plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 1.2.4. This vulnerability arises due to insufficient input sanitization and output escaping within the plugin's core logic. 

The exploit mechanism is unique because it effectively bypasses WordPress core's save-time 'kses' sanitization. Attackers utilize payloads consisting of elements allowed by the core sanitizer, specifically the 'abbr' tag with a 'title' attribute and 'code' text content. The vulnerability is triggered post-save by the plugin's output-buffer rewriter. This component substitutes content into the 'abbr title' attribute using predictable, unsalted placeholders. By crafting a payload that conforms to allowed tags during the initial submission but incorporates double-quote-bearing 'code' blocks during output substitution, an unauthenticated attacker can achieve arbitrary JavaScript execution in the browser of any user who accesses the compromised page. This vulnerability poses a significant risk to site administrators and users, potentially leading to session hijacking, site defacement, or credential theft.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary JavaScript in the context of a victim's browser session. This can be used to perform actions on behalf of the user, steal session cookies, or redirect visitors to malicious sites. Given that this vulnerability exists in a popular performance plugin, any WordPress site running version 1.2.4 or lower is at risk of complete compromise of the visitor-facing side of their web application.

## Recommendation

* Immediately update the 'Flying Scripts: Delay JavaScript to Improve Site Speed & Performance' plugin to the latest version, ensuring the patch for CVE-2026-109990 is applied.
* Audit WordPress comment sections for unexpected 'abbr' tags with unusual 'title' attributes, as these are primary indicators of the malicious payload injection.
* Review web server logs for suspicious POST requests targeting comment submission endpoints that contain HTML tags or encoded characters.
* Implement a robust Content Security Policy (CSP) to restrict the execution of unauthorized inline scripts, which provides a layer of defense-in-depth against stored XSS vulnerabilities.
