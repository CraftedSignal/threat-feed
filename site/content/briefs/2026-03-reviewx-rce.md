---
title: ReviewX WordPress Plugin Arbitrary Method Call Vulnerability
slug: 2026-03-reviewx-rce
description: The ReviewX WordPress plugin is vulnerable to arbitrary method calls, allowing unauthenticated attackers to potentially achieve remote code execution.
date: "2026-03-24T12:00:00Z"
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

The ReviewX – WooCommerce Product Reviews plugin for WordPress, a tool designed to enhance product reviews, contains a critical vulnerability. Identified as CVE-2025-10679, this flaw stems from insufficient input validation within the `bulkTenReviews` function. Exploitation allows unauthenticated attackers to invoke arbitrary PHP class methods that either require no input or can utilize default values. This vulnerability affects ReviewX plugin versions up to and including 2.2.12. Successful…
