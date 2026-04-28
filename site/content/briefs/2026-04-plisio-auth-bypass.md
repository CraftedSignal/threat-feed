---
title: Plisio Accept Cryptocurrencies Plugin Missing Authorization Vulnerability (CVE-2026-6372)
slug: 2026-04-plisio-auth-bypass
description: A missing authorization vulnerability in the Plisio Accept Cryptocurrencies with Plisio WordPress plugin (versions up to 2.0.5) allows attackers to bypass payment verification due to incorrectly configured access control security levels.
date: "2026-04-16T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: url
    value: https://patchstack.com/database/wordpress/plugin/plisio-payment-gateway-for-woocommerce/vulnerability/wordpress-accept-cryptocurrencies-with-plisio-plugin-2-0-5-payment-bypass-vulnerability?_s_id=cve
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

CVE-2026-6372 is a missing authorization vulnerability affecting the Plisio Accept Cryptocurrencies with Plisio WordPress plugin, specifically versions from initial releases through 2.0.5. Discovered by Patchstack, the vulnerability stems from incorrectly configured access control security levels within the plugin. An attacker can exploit this flaw to bypass payment verification processes, potentially leading to unauthorized transactions or manipulation of payment-related functionalities. Given the increasing adoption of cryptocurrency payments, this vulnerability presents a significant risk to e-commerce sites using the affected plugin. Successful exploitation can result in financial losses and reputational damage.

## Attack Chain

1.  Attacker identifies a WordPress site using the vulnerable Plisio plugin (version <= 2.0.5).
2.  Attacker analyzes the plugin's code or intercepts network traffic to identify the specific endpoint or function responsible for payment verification lacking proper authorization checks.
3.  The attacker crafts a malicious HTTP request to the vulnerable endpoint, bypassing the intended authentication or authorization mechanisms.
4.  The crafted request modifies payment parameters (e.g., amount, recipient) without proper validation.
5.  The modified request is sent to the server, which processes it without correctly verifying the user's authority.
6.  The server updates the payment status, marking it as "paid" or "verified," even though the actual payment might be incomplete, altered, or entirely missing.
7.  The WordPress site delivers goods or services based on the fraudulently verified payment status.

## Impact

Successful exploitation of CVE-2026-6372 allows attackers to bypass payment verification processes in e-commerce sites using the Plisio Accept Cryptocurrencies plugin. This can lead to financial losses for the site owner due to unauthorized transactions. The vulnerability affects all installations using versions up to and including 2.0.5. Given the potential for widespread impact on any site accepting cryptocurrency via this plugin, this issue represents a high risk.

## Recommendation

*   Upgrade the Plisio Accept Cryptocurrencies with Plisio plugin to a version greater than 2.0.5 to patch CVE-2026-6372.
*   Deploy the Sigma rule `Detect Plisio Payment Bypass Attempt` to monitor for exploit attempts targeting the vulnerable endpoint.
*   Examine web server logs for suspicious POST requests to payment processing endpoints associated with the Plisio plugin, filtering for unexpected parameter modifications (log source: webserver).
