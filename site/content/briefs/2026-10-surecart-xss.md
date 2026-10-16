---
title: Stored Cross-Site Scripting in SureCart WordPress Plugin
slug: 2026-10-surecart-xss
description: The SureCart plugin for WordPress (<= 4.9.4) is vulnerable to Stored Cross-Site Scripting (XSS) via the comment parameter, allowing unauthenticated attackers to execute arbitrary scripts in the context of victims viewing specific e-commerce pages.
date: "2026-10-16T10:25:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:surecart:surecart:*:*:*:*:*:wordpress:*:*
vendors:
  - SureCart
products:
  - SureCart (<= 4.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The SureCart plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'comment' parameter in all versions up to, and including, 4.9.4 due to insufficient input sanitization and output escaping.
    confidence_band: high
cves:
  - id: CVE-2026-109224
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109224
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update SureCart plugin to the latest version to address CVE-2026-109224
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Implement a Content Security Policy (CSP) to block inline script execution
      owner: Security Operations
      addresses: CVE-2026-109224
      evidence: General XSS mitigation guidance
---

The SureCart plugin for WordPress (up to and including version 4.9.4) contains a critical Stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-109224. The vulnerability stems from insufficient input sanitization and output escaping on the 'comment' parameter. An unauthenticated attacker can supply a crafted malicious script payload within a comment field. The script becomes stored in the WordPress database and subsequently executes in the browser of any authenticated or unauthenticated user who visits a page containing the [sc_buy_button] shortcode. Execution is dependent on specific client-side conditions where the page does not contain an 'sc-checkout' element, which triggers an insecure innerHTML sink within the plugin's 'sc-cart-loader' component. This vulnerability poses a significant risk for session hijacking, unauthorized actions on behalf of administrators, or the injection of malicious content into e-commerce storefronts.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's browser. If the victim is an administrator, this can lead to full site compromise, unauthorized configuration changes, or the creation of new administrative accounts. The vulnerability affects any WordPress installation utilizing the SureCart plugin version 4.9.4 or earlier.

## Recommendation

Update the SureCart WordPress plugin to the version containing the security fix (if available, consult the vendor for patches beyond 4.9.4). Monitor web server logs for HTTP POST requests directed at comment submission endpoints that contain script tags or suspicious JavaScript patterns, as these may indicate attempts to inject payloads into the database. Implement strict Content Security Policy (CSP) headers to mitigate the impact of XSS payloads by restricting the execution of inline scripts and unauthorized external resources.
