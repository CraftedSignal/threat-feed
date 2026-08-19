---
title: Unauthenticated Stored XSS in TranslatePress Plugin
slug: 2026-08-translatepress-xss
description: The TranslatePress plugin for WordPress is vulnerable to unauthenticated stored cross-site scripting due to improper handling of translation markers, allowing attackers to inject malicious HTML into post content.
date: "2026-08-19T10:14:30Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TranslatePress
products:
  - TranslatePress – Translate Multilingual sites with AI Translation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The TranslatePress plugin for WordPress is vulnerable to unauthenticated Stored Cross-Site Scripting in versions up to and including 3.2.5.
    confidence_band: high
cves:
  - id: CVE-2026-75981
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75981
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Security Team
  immediate_actions:
    - action: Update TranslatePress plugin to version > 3.2.5
      owner: IT Operations
      due: 24h
      evidence: Plugin version 3.2.5 and below are confirmed vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Review site content for malicious markers
      owner: Web Security Team
      addresses: Stored XSS via TranslatePress markers
      evidence: Attackers use '#!trpst#' and '#!trpen#' markers to inject HTML.
---

The TranslatePress plugin for WordPress (versions 3.2.5 and below) contains a critical security flaw that enables unauthenticated stored cross-site scripting (XSS). The vulnerability exists within the 'translate_page' function in 'includes/class-translation-render.php', which performs an unconditional replacement of the custom gettext markers '#!trpst#' and '#!trpen#' with the HTML brackets '<' and '>'. Because these markers are treated as plain text by standard WordPress sanitization filters like 'wp_kses', they pass through unchanged into the database. When a visitor views a post or comment in a language targeted by the plugin, the rendering engine replaces the markers with HTML tags, allowing an attacker to inject arbitrary HTML, including event handlers like 'onerror'. Because the plugin's 'remove_tags_from_output' function only targets '&lt;script>' and '&lt;style>' tags, attackers can successfully execute JavaScript using alternative tags such as '&lt;img>'. This vulnerability poses a significant risk to site visitors, potentially leading to session theft or administrative account compromise if a privileged user views the injected content.

## Attack Chain

1. Attacker identifies a WordPress site utilizing the vulnerable TranslatePress plugin (version <= 3.2.5).
2. Attacker crafts a malicious payload using the plugin's specific markers, such as '#!trpst#img src=x onerror=alert(1)#!trpen#'.
3. Attacker submits the payload via a vector that accepts user-supplied content, such as a post comment or a custom form field.
4. The WordPress site stores the payload in the database because 'wp_kses' does not recognize the markers as HTML.
5. The attacker waits for an unsuspecting victim or site administrator to load the page with the TranslatePress plugin enabled.
6. The TranslatePress 'translate_page()' function processes the stored comment and substitutes the markers with real HTML brackets.
7. The browser renders the resulting &lt;img> tag, and the 'onerror' event handler executes the malicious JavaScript payload in the victim's session.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the context of the victim's browser session. This can lead to the theft of session cookies, redirection of users to malicious domains, or unauthorized actions performed on behalf of the logged-in user. Given that WordPress sites often attract administrative users to comment threads or post editing interfaces, the risk of credential or session hijacking is high.

## Recommendation

* Immediately update the TranslatePress plugin to the latest version, which contains the patch for this vulnerability.
* Audit existing comments and posts on the site for the presence of the '#!trpst#' or '#!trpen#' substrings as an indicator of potential past exploitation.
* Implement a strong Content Security Policy (CSP) to restrict the execution of unauthorized scripts and mitigate the impact of potential XSS vulnerabilities.
