---
title: Stored XSS in European VAT Compliance Assistant for WooCommerce
slug: 2026-10-european-vat-plugin-xss
description: The European VAT Compliance Assistant for WooCommerce plugin is vulnerable to unauthenticated stored cross-site scripting via the CF-IPCountry HTTP header.
date: "2026-10-17T08:49:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp-vat:european_vat_compliance_assistant_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - European VAT Compliance Assistant for WooCommerce (<= 1.36.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Web Shell: Web Application Extension'
    evidence: The malicious header value is persisted verbatim into order post-meta during a guest checkout.
    confidence_band: high
cves:
  - id: CVE-2026-100316
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100316
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade European VAT Compliance Assistant for WooCommerce to version 1.36.11 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 1.36.10.
  mitigation_plan:
    - priority: immediate
      action: Apply Content Security Policy to WordPress dashboard.
      owner: Security Operations
      addresses: CVE-2026-100316
      evidence: Mitigate impact of stored XSS.
---

The European VAT Compliance Assistant for WooCommerce plugin for WordPress, in all versions up to and including 1.36.10, contains a stored cross-site scripting (XSS) vulnerability. The flaw stems from insufficient input sanitization and output escaping of the 'CF-IPCountry' HTTP header. Unauthenticated attackers can exploit this during the guest checkout process by injecting arbitrary web scripts into the header value. The plugin persists this malicious payload directly into the order post-meta. The injected script then executes whenever an administrative or privileged user views the compromised order data in the WordPress dashboard. Because the injection occurs during a standard guest checkout flow, it requires no authentication, allowing for unauthenticated exploitation to potentially achieve administrative session hijacking.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of the WordPress administrative interface. This can lead to administrative session hijacking, unauthorized modification of site content, creation of rogue administrator accounts, or redirection of legitimate users to malicious sites. The vulnerability affects all sites running the vulnerable plugin version (<= 1.36.10) where Cloudflare or similar infrastructure might pass the 'CF-IPCountry' header.

## Recommendation

* Immediately update the 'European VAT Compliance Assistant for WooCommerce' plugin to the latest available version beyond 1.36.10.
* Audit WordPress order metadata for suspicious script tags or obfuscated JavaScript patterns if the site logs indicate previous exploitation attempts via the 'CF-IPCountry' header.
* Implement strict Content Security Policy (CSP) headers to mitigate the impact of XSS by restricting the execution of unauthorized scripts.
