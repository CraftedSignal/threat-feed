---
title: Adobe Commerce Incorrect Authorization Vulnerability (CVE-2026-34645)
slug: 2026-05-adobe-commerce-authz-bypass
description: Adobe Commerce versions 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, 2.4.4-p17 and earlier are affected by an Incorrect Authorization vulnerability (CVE-2026-34645) that could allow an attacker to bypass security measures and gain unauthorized write access without user interaction.
date: "2026-05-12T20:18:33Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - security-bypass
  - web-application
vendors:
  - Adobe
products:
  - Commerce <= 2.4.9-beta1
  - Commerce <= 2.4.8-p4
  - Commerce <= 2.4.7-p9
  - Commerce <= 2.4.6-p14
  - Commerce <= 2.4.5-p16
  - Commerce <= 2.4.4-p17
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-34645
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34645
  - https://helpx.adobe.com/security/products/magento/apsb26-49.html
rules:
  - title: Detect CVE-2026-34645 Exploitation Attempt — Unauthorized Write Access
    description: Detects CVE-2026-34645 exploitation attempt — HTTP POST requests to sensitive endpoints without proper authorization, potentially indicating unauthorized write access attempts in Adobe Commerce.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-34645 Exploitation Attempt — GraphQL Unauthorized Access
    description: Detects CVE-2026-34645 exploitation attempt — HTTP POST requests to the GraphQL endpoint without valid authentication headers, which could indicate an attempt to bypass security restrictions in Adobe Commerce.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
rules_count: 2
---

Adobe Commerce, formerly Magento, is a popular e-commerce platform. CVE-2026-34645 is an incorrect authorization vulnerability affecting Adobe Commerce versions 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, 2.4.4-p17 and earlier. The vulnerability allows an attacker to bypass security features and gain unauthorized write access to the system. This can be exploited without any user interaction. Successful exploitation could lead to a complete compromise of the e-commerce platform, allowing attackers to modify prices, access sensitive customer data, or inject malicious code. Due to the widespread use of Adobe Commerce, this vulnerability poses a significant risk to online businesses.

## Attack Chain

1.  The attacker identifies an Adobe Commerce instance running a vulnerable version.
2.  The attacker crafts a malicious HTTP request that targets an endpoint requiring authorization.
3.  Due to the incorrect authorization check (CWE-863), the request bypasses the intended security controls.
4.  The attacker gains unauthorized write access to sensitive data or functionality.
5.  The attacker modifies product prices, promotions, or other critical data.
6.  The attacker injects malicious code into the e-commerce platform, potentially leading to remote code execution.

## Impact

Successful exploitation of CVE-2026-34645 can have severe consequences for affected Adobe Commerce stores. An attacker can gain unauthorized write access, enabling them to modify prices, promotions, and potentially access or modify sensitive customer data. This can lead to financial losses, reputational damage, and legal liabilities. Given the wide deployment of Adobe Commerce, a successful widespread attack could impact thousands of online businesses.

## Recommendation

*   Upgrade to the latest version of Adobe Commerce to patch CVE-2026-34645.
*   Monitor web server logs for suspicious activity, such as unexpected POST requests or attempts to access restricted resources.
*   Implement a Web Application Firewall (WAF) with rules to detect and block exploitation attempts targeting the vulnerability (see example Sigma rules below).
