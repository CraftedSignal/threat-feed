---
title: Stored DOM-Based XSS in Photo Reviews for WooCommerce Plugin
slug: 2026-10-photo-reviews-xss
description: The Photo Reviews for WooCommerce plugin for WordPress contains a Stored DOM-Based XSS vulnerability (CVE-2026-100161) allowing unauthenticated attackers to inject malicious scripts into product reviews.
date: "2026-10-10T07:52:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:photo_reviews_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - Photo Reviews for WooCommerce (<= 1.2.30)
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
    evidence: unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-100161
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100161
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Photo Reviews for WooCommerce plugin to a version patched against CVE-2026-100161
      owner: IT Operations
      addresses: CVE-2026-100161
      evidence: Plugin is vulnerable to Stored DOM-Based Cross-Site Scripting in all versions up to, and including, 1.2.30.
---

The Photo Reviews for WooCommerce plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Scripting (XSS) via the 'wcpr_image_upload_id' parameter in all versions up to, and including, 1.2.30. This vulnerability arises from insufficient input sanitization and output escaping. An unauthenticated attacker can exploit this flaw because the plugin fails to perform necessary capability or ownership checks when processing the 'wcpr_image_upload' nonce. The malicious payload is stored within comment metadata, which is not subjected to 'wp_kses' filtering. Consequently, the injected JavaScript executes in the browser of any user viewing the affected product review page on the frontend. This vulnerability poses a significant risk for session hijacking, unauthorized actions, and credential theft, particularly if administrative users view the compromised content.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of other users' sessions. This can lead to the theft of session cookies, unauthorized modification of website content, or the execution of malicious actions on behalf of administrators or customers, significantly impacting the integrity and security of the affected WordPress site.

## Recommendation

Update the Photo Reviews for WooCommerce plugin to the latest available version (beyond 1.2.30) where the input sanitization and nonce verification have been patched. Security teams should scan the WordPress database for anomalous JavaScript patterns injected into wp_comments or associated comment metadata.
