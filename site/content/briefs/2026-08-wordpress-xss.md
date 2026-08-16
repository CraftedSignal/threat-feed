---
title: Stored XSS Vulnerability in Platnosci Online Blue Media Plugin
slug: 2026-08-wordpress-xss
description: An unauthenticated stored Cross-Site Scripting vulnerability in the Platnosci Online Blue Media WordPress plugin allows attackers to inject malicious scripts into the checkout page.
date: "2026-08-16T06:24:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - xss
  - wordpress
  - plugin-security
vendors:
  - Autopay
products:
  - Platnosci Online Blue Media (Autopay) plugin
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
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The raw $_POST value is written to the 'woocommerce_bluemedia_settings' option... then later echoed directly inside a <style> block... with no output escaping.
    confidence_band: high
cves:
  - id: CVE-2026-15002
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15002
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected plugin version
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions up to and including 5.0.0
  mitigation_plan:
    - priority: immediate
      action: WAF rules for bm_woocommerce_css_editor_content
      owner: SOC
      addresses: CVE-2026-15002
      evidence: Unauthenticated attacker can inject arbitrary web scripts
---

The Platnosci Online Blue Media (Autopay) plugin for WordPress (versions 5.0.0 and below) contains a critical stored Cross-Site Scripting (XSS) vulnerability. The flaw originates in the Css_Editor::handle_save() method, which is improperly registered to the WordPress 'init' hook via Settings_Manager::init_once(). This method fails to implement necessary capability checks, nonce verification, or input sanitization on the 'bm_woocommerce_css_editor_content' POST parameter. Consequently, the plugin stores raw user-provided input directly into the 'woocommerce_bluemedia_settings' database option.

When a user visits the WooCommerce checkout page, the Css_Frontend::print_to_wp_head() function retrieves this stored value and echoes it directly into a &lt;style> block without output escaping. An unauthenticated attacker can leverage this injection point to execute arbitrary JavaScript in the context of the victim's session, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of the site user. The scope of this threat is significant given the plugin's integration into the checkout process, which is a high-value target for attackers.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code in the browser context of any user viewing the WooCommerce checkout page. This can lead to full site administrative compromise if a site administrator views the page, or the theft of customer session cookies and sensitive checkout information. The vulnerability affects all WordPress installations utilizing the Platnosci Online Blue Media plugin up to version 5.0.0.

## Recommendation

Prioritized, concrete actions for detection and remediation:
- Update the Platnosci Online Blue Media (Autopay) plugin to the latest available version beyond 5.0.0 immediately.
- Deploy WAF rules to inspect HTTP POST requests for the 'bm_woocommerce_css_editor_content' parameter to detect script-like payloads (e.g., &lt;script>, javascript:, or event handlers).
- Implement access control list (ACL) restrictions at the web server level to limit access to the endpoints responsible for updating settings if the plugin functionality is not strictly required.
- Review web server access logs for anomalous POST requests targeting the WordPress site with the identified parameter.
