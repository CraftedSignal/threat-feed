---
title: Product Feed PRO for WooCommerce Plugin CSRF Vulnerability (CVE-2026-3499)
slug: 2026-04-woocommerce-csrf
description: The Product Feed PRO for WooCommerce WordPress plugin (versions 13.4.6-13.5.2.1) is vulnerable to Cross-Site Request Forgery (CSRF) attacks, allowing unauthenticated attackers to perform administrative actions by tricking an administrator into clicking a malicious link.
date: "2026-04-08T02:16:04Z"
severities:
  - high
type: advisory
types:
  - advisory
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

The Product Feed PRO for WooCommerce by AdTribes – Product Feeds for WooCommerce plugin, a WordPress plugin, suffers from a Cross-Site Request Forgery (CSRF) vulnerability. Present in versions 13.4.6 through 13.5.2.1, this flaw allows unauthenticated attackers to execute administrative functions if they can successfully coerce a site administrator into performing an action, such as clicking a specially crafted link. The vulnerability stems from the plugin's failure to implement proper nonce validation on several AJAX actions, including `ajax_migrate_to_custom_post_type`, `ajax_adt_clear_custom_attributes_product_meta_keys`, `ajax_update_file_url_to_lower_case`, `ajax_use_legacy_filters_and_rules`, and `ajax_fix_duplicate_feed`. This vulnerability poses a significant risk to WooCommerce store owners using the affected plugin.

## Attack Chain

1.  The attacker crafts a malicious URL containing a request to one of the vulnerable AJAX actions (e.g., `ajax_migrate_to_custom_post_type`).
2.  The attacker distributes the malicious URL via email, social media, or another channel, attempting to trick a WordPress administrator into clicking the link.
3.  The administrator, while authenticated to the WordPress admin panel, clicks the malicious link.
4.  The administrator's browser sends the forged request to the WordPress server, including the administrator's session cookies.
5.  Due to the missing or incorrect nonce validation, the WordPress server processes the request as if it were a legitimate action performed by the administrator.
6.  Depending on the specific AJAX action targeted, the attacker can trigger feed migration, clear custom attribute caches, rewrite feed file URLs to lowercase, toggle legacy filter and rule settings, or delete duplicate feed posts.
7.  The attacker repeats this process to perform other administrative actions, gaining control over the plugin's settings and data.
8.  The attacker potentially manipulates product feeds to inject malicious content, redirect users, or compromise the WooCommerce store's SEO.

## Impact

Successful exploitation of this CSRF vulnerability (CVE-2026-3499) could allow an attacker to manipulate a WooCommerce store's product feeds, potentially leading to data corruption, SEO poisoning, or the injection of malicious content. If successful, attackers could modify product information, redirect users to phishing sites, or damage the store's reputation. The severity of the impact depends on the targeted AJAX action, but the potential for unauthorized administrative control is significant. Given the wide usage of WooCommerce and the Product Feed PRO plugin, a large number of online stores are potentially at risk.

## Recommendation

*   Upgrade the Product Feed PRO for WooCommerce plugin to a patched version greater than 13.5.2.1 to remediate CVE-2026-3499.
*   Deploy the provided Sigma rules to your SIEM to detect exploitation attempts targeting the vulnerable AJAX actions.
*   Implement web application firewall (WAF) rules to block requests to the vulnerable AJAX endpoints originating from suspicious referrers.
*   Educate WordPress administrators on the risks of CSRF attacks and the importance of verifying links before clicking them.
