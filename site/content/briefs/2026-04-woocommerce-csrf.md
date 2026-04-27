---
title: Product Feed PRO for WooCommerce Plugin CSRF Vulnerability (CVE-2026-3499)
slug: 2026-04-woocommerce-csrf
description: The Product Feed PRO for WooCommerce WordPress plugin (versions 13.4.6-13.5.2.1) is vulnerable to Cross-Site Request Forgery (CSRF) attacks, allowing unauthenticated attackers to perform administrative actions by tricking an administrator into clicking a malicious link.
date: "2026-04-08T02:16:04Z"
severities:
  - high
tags:
  - wordpress
  - woocommerce
  - csrf
  - cve-2026-3499
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Supply Chain Compromise
cves:
  - id: CVE-2026-3499
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3499
rules:
  - title: Detect Product Feed PRO WooCommerce Plugin CSRF - Migrate to Custom Post Type
    description: Detects potential CSRF attempts to trigger the ajax_migrate_to_custom_post_type action in the Product Feed PRO plugin.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1565.001
    data_sources:
      - webserver
      - linux
  - title: Detect Product Feed PRO WooCommerce Plugin CSRF - Clear Custom Attributes
    description: Detects potential CSRF attempts to clear custom attributes using the ajax_adt_clear_custom_attributes_product_meta_keys action.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1565.001
    data_sources:
      - webserver
      - linux
  - title: Detect Product Feed PRO WooCommerce Plugin CSRF - File URL Lowercase Rewrite
    description: Detects potential CSRF attempts to rewrite feed file URLs using ajax_update_file_url_to_lower_case.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1565.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

The Product Feed PRO for WooCommerce by AdTribes – Product Feeds for WooCommerce plugin, a WordPress plugin, suffers from a Cross-Site Request Forgery (CSRF) vulnerability. Present in versions 13.4.6 through 13.5.2.1, this flaw allows unauthenticated attackers to execute administrative functions if they can successfully coerce a site administrator into performing an action, such as clicking a specially crafted link. The vulnerability stems from the plugin's failure to implement proper nonce…
