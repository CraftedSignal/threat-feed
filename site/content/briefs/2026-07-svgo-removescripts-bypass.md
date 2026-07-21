---
title: SVGO removeScripts Plugin Bypass Leads to Cross-Site Scripting
slug: 2026-07-svgo-removescripts-bypass
description: A vulnerability in the SVGO library's `removeScripts` plugin, affecting versions prior to 2.8.3, 3.3.4, and 4.0.2, allowed namespaced script elements and case-insensitive JavaScript URIs to bypass sanitization, potentially leading to Cross-Site Scripting (XSS) in web applications serving untrusted SVGs.
date: "2026-07-21T19:43:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - svg
  - sanitization-bypass
  - web-vulnerability
vendors:
  - SVGO
products:
  - SVGO (< 2.8.3)
  - SVGO (< 3.3.4)
  - SVGO (< 4.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker could leverage this to execute arbitrary JavaScript in a victim's browser
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: An attacker could leverage this to execute arbitrary JavaScript in a victim's browser, potentially stealing session cookies or local storage data.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2p49-hgcm-8545
---

A significant vulnerability has been identified in the `removeScripts` plugin of the SVGO library, a Node.js-based tool for optimizing SVG files. This plugin, although disabled by default, was intended to sanitize SVG files by removing executable JavaScript. However, it failed to adequately detect and remove certain types of malicious scripts, specifically those using namespaced `<svg:script>` elements or case-insensitive `JavaScript:` URIs. This oversight means that web applications relying on SVGO with this plugin enabled for sanitization of untrusted user-supplied SVG content could inadvertently host and serve malicious SVGs. If a victim user then accesses these unsanitized SVGs through the same domain, attackers could execute arbitrary JavaScript within their browser, leading to Cross-Site Scripting (XSS) attacks. Such attacks could compromise user sessions by stealing cookies or other sensitive local storage data.

## Attack Chain

1. An attacker crafts a malicious SVG file containing an embedded script using either a namespaced `<svg:script>` element (e.g., `<svg:script>alert(document.cookie);</svg:script>`) or a case-insensitively encoded JavaScript URI (e.g., `<a uwu:href="JavaScript:(() => { alert(document.cookie) })();">`).
2. The attacker uploads this malicious SVG to a web application that accepts user-supplied SVG content and utilizes the SVGO library with the `removeScripts` plugin enabled for sanitization.
3. The web application processes the uploaded SVG using SVGO. Due to the vulnerability, the `removeScripts` plugin fails to identify and remove the maliciously crafted script elements.
4. The unsanitized, malicious SVG is stored by the web application.
5. A victim user accesses a web page on the same domain that dynamically loads or displays the previously uploaded malicious SVG.
6. The victim's web browser renders the SVG content. Since the malicious script was not removed, the embedded JavaScript is executed within the context of the victim's browser session.
7. The executed JavaScript (e.g., `alert(document.cookie)`) can then perform actions such as stealing session cookies, local storage data, or defacing the web page, leading to Cross-Site Scripting (XSS).

## Impact

If organizations run SVGO on untrusted input, such as user uploads to a web application, and depend on the `removeScripts` plugin for sanitization, this vulnerability directly impacts their users. Unsanitized SVGs could be served to other users, leading to Cross-Site Scripting (XSS). This allows attackers to execute arbitrary client-side script code in the victim's browser. The potential consequences include session hijacking through stolen `document.cookie` or `localStorage` data, defacement of the affected web page, redirection to malicious sites, or other client-side attacks. The vulnerability affects SVGO versions prior to 2.8.3, 3.3.4, and 4.0.2. It is less likely to impact users who only use SVGO locally or in build pipelines where untrusted input is not processed for public consumption.

## Recommendation

* Upgrade SVGO dependencies immediately for versions 3.0.0 through 4.0.1 to >=4.0.2 or >=3.3.4 to mitigate the vulnerability.
* Upgrade SVGO dependencies immediately for versions 2.0.0 through 2.8.2 to >=2.8.3 to mitigate the vulnerability in the `<script>` elements. Note that v2 does not remove JavaScript URIs or event handlers.
* For users on SVGO v1.x.x, upgrade to a more recent version as v1 is deprecated and will not receive patches.
* If SVG sanitization is a critical requirement, consider using a dedicated SVG sanitization library as a workaround before passing SVGs to SVGO for optimization.
