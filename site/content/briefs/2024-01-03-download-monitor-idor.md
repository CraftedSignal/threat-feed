---
title: Download Monitor WordPress Plugin Insecure Direct Object Reference
slug: 2024-01-03-download-monitor-idor
description: The Download Monitor plugin for WordPress is vulnerable to Insecure Direct Object Reference (IDOR) allowing unauthenticated attackers to steal paid digital goods by manipulating PayPal transaction tokens to complete arbitrary orders.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - idor
  - download-monitor
  - cve-2026-3124
vendors:
  - Download Monitor
products:
  - Download Monitor plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3124
rules:
  - title: Detect Suspicious Download Monitor Payment Execution
    description: Detects potential exploitation of the Download Monitor IDOR vulnerability by monitoring POST requests to executePayment with potentially manipulated parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Download Monitor Plugin Access
    description: Detects access to the download monitor plugin files
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Download Monitor plugin for WordPress, versions 5.1.7 and earlier, contains an Insecure Direct Object Reference (IDOR) vulnerability. This flaw resides within the `executePayment()` function, stemming from inadequate validation of a user-controlled key. An unauthenticated attacker can exploit this vulnerability by manipulating the PayPal transaction token associated with pending orders. The attacker can essentially "swap" a payment token from a low-value purchase to finalize a high-value order, effectively stealing digital goods. This attack does not require any prior authentication or knowledge of the system beyond the presence of the vulnerable plugin. This vulnerability poses a significant risk to websites that rely on the Download Monitor plugin to sell digital products, as it allows attackers to bypass payment for valuable content.

## Attack Chain

1. The attacker identifies a WordPress website using the vulnerable Download Monitor plugin (versions <= 5.1.7).
2. The attacker identifies a high-value digital product offered for sale through the plugin.
3. The attacker purchases a low-value item through the website, completing the PayPal transaction to receive a valid transaction token.
4. The attacker identifies the pending order ID of the high-value product they wish to steal, likely through enumeration or predictable order naming schemes.
5. The attacker crafts a malicious request to the `executePayment()` function, replacing the expected PayPal transaction token for the high-value order with the token obtained from the low-value purchase.
6. The server-side `executePayment()` function fails to properly validate the transaction token against the expected order details.
7. The plugin incorrectly marks the high-value order as "paid" and grants the attacker access to the digital product.
8. The attacker downloads the high-value digital product for free, resulting in financial loss for the website owner.

## Impact

Successful exploitation of this IDOR vulnerability allows unauthenticated attackers to bypass payment and steal digital goods offered through the Download Monitor plugin. The number of affected websites is unknown, but any site using Download Monitor versions 5.1.7 or earlier is vulnerable. The financial impact depends on the value of the digital products offered, and the frequency with which attackers exploit the flaw. Websites selling high-value digital assets are at the greatest risk.

## Recommendation

*   Upgrade the Download Monitor plugin to the latest version, which includes a patch for CVE-2026-3124.
*   Implement the Sigma rule `Detect Suspicious Download Monitor Payment Execution` to identify potential exploitation attempts by monitoring POST requests to `executePayment()` with unusual parameters or token mismatches.
*   Enable web server logging and carefully monitor access logs for POST requests to `/wp-content/plugins/download-monitor/includes/` to enable detections.
*   Implement server-side validation to verify that the PayPal transaction token matches the expected order details before finalizing any order.
