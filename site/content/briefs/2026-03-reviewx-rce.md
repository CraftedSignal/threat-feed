---
title: ReviewX WordPress Plugin Arbitrary Method Call Vulnerability
slug: 2026-03-reviewx-rce
description: The ReviewX WordPress plugin is vulnerable to arbitrary method calls, allowing unauthenticated attackers to potentially achieve remote code execution.
date: "2026-03-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - wordpress
  - woocommerce
  - reviewx
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-10679
rules:
  - title: Detect ReviewX Arbitrary Method Calls
    description: Detects potential exploitation attempts targeting the ReviewX plugin's arbitrary method call vulnerability (CVE-2025-10679) by monitoring for suspicious POST requests to the bulkTenReviews function.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect ReviewX Arbitrary Method Calls RCE via PHP
    description: Detects potential remote code execution attempts after initial arbitrary method call.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The ReviewX – WooCommerce Product Reviews plugin for WordPress, a tool designed to enhance product reviews, contains a critical vulnerability. Identified as CVE-2025-10679, this flaw stems from insufficient input validation within the `bulkTenReviews` function. Exploitation allows unauthenticated attackers to invoke arbitrary PHP class methods that either require no input or can utilize default values. This vulnerability affects ReviewX plugin versions up to and including 2.2.12. Successful exploitation can lead to sensitive information disclosure or, under certain server configurations and available methods, remote code execution. This poses a significant risk to e-commerce sites utilizing the vulnerable plugin, potentially impacting customer data and overall site integrity.

## Attack Chain

1.  The attacker sends a crafted HTTP request to the WordPress server targeting the vulnerable `bulkTenReviews` function in the ReviewX plugin.
2.  The crafted request includes malicious input designed to bypass the insufficient input validation within the `bulkTenReviews` function.
3.  The `bulkTenReviews` function processes the attacker-controlled data without proper sanitization.
4.  The unsanitized input is passed to a variable function call mechanism, allowing the attacker to specify an arbitrary PHP class method.
5.  The attacker leverages this vulnerability to call a PHP class method that requires no inputs or has default values.
6.  Depending on the available methods and server configuration, the attacker may be able to trigger sensitive information disclosure.
7.  In more critical scenarios, the attacker might be able to call methods that allow writing to the file system or executing arbitrary commands, leading to remote code execution.
8.  The attacker gains control of the WordPress server, enabling them to install malware, steal data, or deface the website.

## Impact

Successful exploitation of CVE-2025-10679 can lead to a range of damaging consequences. Sensitive information, such as customer data and administrative credentials, may be exposed. In the worst-case scenario, attackers can achieve remote code execution, granting them complete control over the affected WordPress server. This can result in website defacement, data theft, malware installation, and denial-of-service attacks. Given the wide usage of WooCommerce and ReviewX, a successful widespread attack could impact numerous e-commerce businesses.

## Recommendation

*   Immediately update the ReviewX plugin to the latest version (greater than 2.2.12) to patch CVE-2025-10679.
*   Deploy the Sigma rule `Detect ReviewX Arbitrary Method Calls` to detect exploitation attempts targeting the `bulkTenReviews` function.
*   Monitor web server logs for suspicious POST requests to WordPress plugins with unusual parameters, as highlighted in the Sigma rule `Detect ReviewX Arbitrary Method Calls`.
*   Review PHP configurations to harden against potential RCE attempts stemming from arbitrary method calls.
