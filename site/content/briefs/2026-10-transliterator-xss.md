---
title: Stored Cross-Site Scripting in The Transliterator WordPress Plugin
slug: 2026-10-transliterator-xss
description: An unauthenticated stored XSS vulnerability in The Transliterator plugin (<= 2.5.8) allows attackers to inject malicious JavaScript into WordPress comments, leading to arbitrary code execution in the context of site viewers.
date: "2026-10-03T06:54:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:the_transliterator_multilingual_and_multi_script_text_conversion:*:*:*:*:*:*:*:*
tags:
  - xss
  - wordpress
  - web-vulnerability
vendors:
  - WordPress
products:
  - The Transliterator – Multilingual and Multi-script Text Conversion (<= 2.5.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The payload survives WordPress comment save-time sanitization... that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96575
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96575
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade The Transliterator plugin to the latest version beyond 2.5.8
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 2.5.8
  mitigation_plan:
    - priority: immediate
      action: Disable comment submission for unauthenticated users
      owner: IT Operations
      addresses: CVE-2026-96575
      evidence: Vulnerability is in comment processing
---

The Transliterator - Multilingual and Multi-script Text Conversion plugin for WordPress (all versions up to and including 2.5.8) contains a stored cross-site scripting (XSS) vulnerability. The flaw arises due to insufficient input sanitization and output escaping when processing comment content. Unauthenticated attackers can exploit this by injecting payloads that leverage the plugin's predictable {rstr_keep} placeholder token. Because the WordPress core 'kses' allow-list permits specific HTML tags and attributes (such as 'a' with the 'title' attribute and 'code' tags), the malicious payloads bypass standard save-time sanitization routines. When a site administrator or visitor views a comment containing the injected script, the payload executes within the victim's browser session. This vulnerability poses a significant risk for session hijacking, unauthorized actions performed on behalf of authenticated users, and defacement of the affected WordPress site.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of any user who views the compromised content. This may lead to the theft of session cookies (enabling account takeover), forced redirection to malicious domains, or unauthorized administrative actions if an authenticated WordPress user views the comment.

## Recommendation

* Update The Transliterator plugin to a version released after 2.5.8 immediately.
* If a patched version is not available, disable the plugin or restrict comment submission capabilities for unauthenticated users as a temporary mitigation.
* Implement a strict Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities by restricting the sources of executable scripts.
* Monitor server-side web application logs for unusual POST requests directed at comment submission endpoints that contain suspicious HTML attributes or script tokens.
