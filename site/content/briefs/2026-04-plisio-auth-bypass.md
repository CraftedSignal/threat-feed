---
title: Plisio Accept Cryptocurrencies Plugin Missing Authorization Vulnerability (CVE-2026-6372)
slug: 2026-04-plisio-auth-bypass
description: A missing authorization vulnerability in the Plisio Accept Cryptocurrencies with Plisio WordPress plugin (versions up to 2.0.5) allows attackers to bypass payment verification due to incorrectly configured access control security levels.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - wordpress
  - plugin
  - payment-bypass
  - cve-2026-6372
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-6372
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6372
  - https://patchstack.com/database/wordpress/plugin/plisio-payment-gateway-for-woocommerce/vulnerability/wordpress-accept-cryptocurrencies-with-plisio-plugin-2-0-5-payment-bypass-vulnerability?_s_id=cve
ioc_counts:
  url: 1
rules:
  - title: Detect Plisio Payment Bypass Attempt
    description: Detects potential payment bypass attempts against the Plisio WordPress plugin by monitoring for suspicious POST requests to payment processing endpoints.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Plisio Plugin Directory Access
    description: Detects access to the Plisio plugin directory which might indicate reconnaissance attempts.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6372 is a missing authorization vulnerability affecting the Plisio Accept Cryptocurrencies with Plisio WordPress plugin, specifically versions from initial releases through 2.0.5. Discovered by Patchstack, the vulnerability stems from incorrectly configured access control security levels within the plugin. An attacker can exploit this flaw to bypass payment verification processes, potentially leading to unauthorized transactions or manipulation of payment-related functionalities. Given…
