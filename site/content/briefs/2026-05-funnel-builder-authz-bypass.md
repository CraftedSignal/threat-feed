---
title: Funnel Builder for WooCommerce Checkout Missing Authorization Vulnerability (CVE-2026-47100)
slug: 2026-05-funnel-builder-authz-bypass
description: Funnel Builder for WooCommerce Checkout versions prior to 3.15.0.3 contains a missing authorization vulnerability in the public checkout endpoint that allows unauthenticated attackers to invoke internal methods and inject malicious JavaScript, impacting checkout page visitors.
date: "2026-05-19T15:19:24Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - woocommerce
  - wordpress
  - missing-authorization
  - javascript-injection
vendors:
  - WooCommerce
products:
  - Funnel Builder for WooCommerce Checkout < 3.15.0.3
cves:
  - id: CVE-2026-47100
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47100
  - https://plugins.trac.wordpress.org/changeset/3530797/funnel-builder/tags/3.15.0.3/modules/checkouts/includes/class-wfacp-ajax-controller.php
  - https://sansec.io/research/funnelkit-woocommerce-vulnerability-exploited
  - https://www.vulncheck.com/advisories/funnel-builder-for-woocommerce-checkout-missing-authorization-via-ajax
rules:
  - title: Detect CVE-2026-47100 Exploitation — Funnel Builder Unauthorized Script Injection
    description: Detects CVE-2026-47100 exploitation — Attempts to inject JavaScript code into Funnel Builder's External Scripts setting via unauthorized requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect CVE-2026-47100 Exploitation — Funnel Builder External Scripts Modification
    description: Detects CVE-2026-47100 exploitation — Modification of Funnel Builder external scripts setting with potentially malicious JavaScript.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

A missing authorization vulnerability exists in the Funnel Builder for WooCommerce Checkout plugin (versions prior to 3.15.0.3). This flaw allows unauthenticated attackers to bypass authorization checks in the public checkout endpoint. By invoking internal methods, attackers can write arbitrary data to the plugin's External Scripts global setting. This injection allows the introduction of malicious JavaScript code. This JavaScript then executes in the browsers of all users visiting the checkout page, potentially leading to credential theft, defacement, or other client-side attacks. The vulnerability was reported on May 19, 2026, and is identified as CVE-2026-47100.

## Attack Chain

1. An unauthenticated attacker identifies the vulnerable checkout endpoint in the Funnel Builder plugin.
2. The attacker crafts a malicious HTTP request to the checkout endpoint, bypassing authorization checks.
3. This request invokes an internal method to modify plugin settings.
4. The attacker writes arbitrary data containing malicious JavaScript code to the External Scripts global setting.
5. A user visits the checkout page on the affected WooCommerce site.
6. The injected JavaScript code from the External Scripts setting executes in the user's browser.
7. The malicious JavaScript performs actions such as stealing payment information, redirecting the user to a phishing site, or defacing the page.
8. The attacker gains access to sensitive user data or compromises the integrity of the checkout process.

## Impact

Successful exploitation of this vulnerability allows an attacker to inject malicious JavaScript into the checkout pages of WooCommerce stores using the Funnel Builder plugin. This could lead to the theft of customer payment information, redirection to phishing sites, or defacement of the checkout page, affecting potentially all users visiting the checkout page. Given the widespread use of WooCommerce for e-commerce, a large number of stores and customers are potentially at risk.

## Recommendation

*   Upgrade the Funnel Builder for WooCommerce Checkout plugin to version 3.15.0.3 or later to patch CVE-2026-47100.
*   Deploy the Sigma rule "Detect CVE-2026-47100 Exploitation — Funnel Builder Unauthorized Script Injection" to your SIEM to detect exploitation attempts.
*   Monitor web server logs for suspicious POST requests to checkout endpoints with attempts to modify script settings, as indicated by the log source in the provided Sigma rule.
