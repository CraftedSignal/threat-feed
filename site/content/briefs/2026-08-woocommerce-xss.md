---
title: Stored Cross-Site Scripting in Customer Reviews for WooCommerce
slug: 2026-08-woocommerce-xss
description: Unauthenticated attackers can perform Stored Cross-Site Scripting (XSS) via the 'cr_local_forms_submit' AJAX action in Customer Reviews for WooCommerce versions 5.106.0 and below.
date: "2026-08-28T17:13:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cusrev:customer_reviews_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - Customer Reviews for WooCommerce
products:
  - Customer Reviews for WooCommerce (<= 5.106.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The plugin accepts review submissions from unauthenticated users through the 'cr_local_forms_submit' AJAX action without sanitizing HTML content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses the affected product page.
    confidence_band: high
cves:
  - id: CVE-2026-6176
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6176
rules:
  - title: Detect CVE-2026-6176 Exploitation - AJAX Review Submission with XSS Payloads
    description: Detects exploitation attempts against CVE-2026-6176 where an AJAX request to the cr_local_forms_submit action contains common XSS patterns within the review comment parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Customer Reviews for WooCommerce plugin to version > 5.106.0
      owner: IT Operations
      due: 48h
      evidence: Source confirms vulnerability in versions 5.106.0 and below
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 5.106.1 or later
      owner: IT Operations
      addresses: CVE-2026-6176
      evidence: NVD vulnerability details
---

The Customer Reviews for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in versions up to and including 5.106.0. The vulnerability stems from the plugin's 'cr_local_forms_submit' AJAX action, which fails to adequately sanitize user-supplied review content before it is stored in the database via the 'wp_insert_comment' function. Furthermore, the plugin fails to perform proper output escaping when rendering this content on product pages using 'comment_text()'. 

An unauthenticated attacker can exploit this by submitting malicious scripts within review comments. By leveraging legitimate review form URLs, typically delivered via email to previous customers, an attacker can inject scripts that execute in the browser of any user who views the compromised product page. Successful exploitation may lead to session hijacking, unauthorized actions performed on behalf of authenticated administrators or users, or redirection to malicious sites.

## Impact

The vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in the context of victim browsers. This poses a significant risk to WordPress sites using the plugin, particularly if administrative accounts view the affected product pages. Potential consequences include account takeover, credential theft, and unauthorized site modifications.

## Recommendation

* Upgrade the 'Customer Reviews for WooCommerce' plugin to the latest version immediately to patch CVE-2026-6176.
* Audit existing product comments for unexpected HTML or script tags if the site was running version 5.106.0 or earlier.
* Implement or strengthen Content Security Policy (CSP) headers to restrict the execution of unauthorized inline scripts.
