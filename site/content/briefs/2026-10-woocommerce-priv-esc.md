---
title: CVE-2026-104745 - Privilege Escalation in Customer Email Verification for WooCommerce
slug: 2026-10-woocommerce-priv-esc
description: The Customer Email Verification for WooCommerce plugin for WordPress is vulnerable to unauthenticated privilege escalation due to insufficient entropy in activation token generation when configured to use the 'hashids' encoding method.
date: "2026-10-16T04:24:03Z"
lastmod: "2026-10-16T07:31:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:alg_wc_ev:customer_email_verification_for_woocommerce:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=772F5118-FA06-5ECC-8E1F-99221D0D325C&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - wordpress
  - privilege-escalation
  - cve-2026-104745
vendors:
  - WordPress
products:
  - Customer Email Verification for WooCommerce (<= 3.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: This makes it possible for unauthenticated attackers to gain authentication as any unverified WordPress account, including administrator-level accounts, by brute-forcing the trivially small activation code space via a forged verification URL.
    confidence_band: high
cves:
  - id: CVE-2026-104745
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104745
  - https://sploitus.com/exploit?id=772F5118-FA06-5ECC-8E1F-99221D0D325C&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-104745 Exploitation - Brute Force Attempt on Email Verification
    description: Detects high-frequency access to the verification parameter indicating potential brute-force attempts against the weak token generation mechanism.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1595.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit user accounts for unverified status and ensure plugin is patched or disabled.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104745 vulnerability description
  hunt_leads:
    - lead: Search web logs for high-frequency access to the alg_wc_ev_verify_email parameter.
      technique_id: T1595.002
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source states brute-force of code space is possible.
  mitigation_plan:
    - priority: immediate
      action: Update Customer Email Verification for WooCommerce plugin to version > 3.3.0 or change 'Encoding method' setting.
      owner: IT Operations
      addresses: CVE-2026-104745
      evidence: Vulnerability exists in versions up to 3.3.0.
updates:
  - at: "2026-10-16T07:31:17Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=772F5118-FA06-5ECC-8E1F-99221D0D325C&utm_source=rss&utm_medium=rss
---

The Customer Email Verification for WooCommerce plugin for WordPress, in versions up to and including 3.3.0, contains a critical security flaw that allows for unauthenticated privilege escalation. When the plugin is configured with the 'hashids' encoding method, it generates per-user activation secrets using the `wp_rand(100)` function. This results in an extremely low entropy of approximately 101 possible values, or 7 bits. Because these tokens are generated via reversible Hashids encoding without a cryptographic MAC, and because the verification handler hooked to the WordPress `init` action lacks nonce verification or rate limiting, an attacker can brute-force the activation code space. By supplying a forged `alg_wc_ev_verify_email` GET parameter, an unauthenticated attacker can verify and hijack unverified accounts, including those with administrative privileges, provided the attacker can recover or guess the Hashids salt, which typically defaults to an `md5(time())` value generated at initial setup.

## Impact

Successful exploitation allows an unauthenticated attacker to hijack any unverified WordPress account, including administrator accounts. This leads to full administrative control over the WordPress instance, enabling arbitrary code execution, data exfiltration, and full site compromise. This vulnerability impacts all WordPress environments utilizing the specified plugin version with the non-default 'hashids' configuration enabled.

## Recommendation

* Update the 'Customer Email Verification for WooCommerce' plugin to the latest version patched against CVE-2026-104745.
* If patching is not immediately feasible, change the plugin's 'Encoding method' from 'hashids' to a more secure alternative or disable the plugin entirely.
* Audit the WordPress user database for unverified accounts that could be targeted for hijacking.
* Monitor web server logs for high-frequency GET requests containing the `alg_wc_ev_verify_email` parameter targeting the WordPress home directory or specific verification endpoints.
