---
brief_id: brief-2026-05-02-wordpress-auth-bypass
event_id: brief-2026-05-02-wordpress-auth-bypass
revision: 2
activity_at: "2026-11-23T10:28:26Z"
revision_history:
  - revision: 2
    at: "2026-11-23T10:28:26Z"
    checksum: sha256:93d5759caa36bee82b801309a55d5178cde392c1d82171b17a44cb051d7b05a5
    summary: poc_available
    changed_fields:
      - cpes
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SANGSENIMANWARTEFAK-CVE-2026-7458&utm_source=rss&utm_medium=rss
title: WordPress User Verification Plugin Authentication Bypass Vulnerability
slug: 2026-05-wordpress-auth-bypass
description: The User Verification by PickPlugins plugin for WordPress is vulnerable to authentication bypass in versions up to 2.0.46 due to a loose PHP comparison, allowing unauthenticated attackers to log in as any verified user by submitting a 'true' OTP value.
date: "2026-05-02T05:16:01Z"
lastmod: "2026-11-23T10:28:11Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:pickplugins:user_verification_by_pickplugins_plugin_for_wordpress_2_0_46:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SANGSENIMANWARTEFAK-CVE-2026-7458&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - authentication bypass
  - cve-2026-7458
vendors:
  - PickPlugins
products:
  - User Verification by PickPlugins plugin for WordPress <= 2.0.46
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cve_verification:
  CVE-2026-7458:
    status: verified
    source: nvd
    checked_at: 2026-11-23T10:28:11.421789458Z
cves:
  - id: CVE-2026-7458
    cvss: 9.8
    epss: 0.00578
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7458
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/35b86488-8f68-4738-a9a8-76d0b7976165?source=cve
  - https://plugins.trac.wordpress.org/changeset/3519113/user-verification
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SANGSENIMANWARTEFAK-CVE-2026-7458&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Attempted Authentication Bypass via True OTP
    description: Detects attempts to exploit the authentication bypass vulnerability (CVE-2026-7458) by submitting 'true' as an OTP value in WordPress logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1078
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Successful Authentication Bypass via True OTP
    description: Detects successful authentication using the bypass vulnerability (CVE-2026-7458) in WordPress logs, indicated by a successful login immediately following a 'true' OTP attempt.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1078
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-11-23T10:28:11Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SANGSENIMANWARTEFAK-CVE-2026-7458&utm_source=rss&utm_medium=rss
---

## Overview

The User Verification by PickPlugins plugin, a popular WordPress plugin, contains a critical authentication bypass vulnerability (CVE-2026-7458) affecting all versions up to and including 2.0.46. The flaw resides within the `user_verification_form_wrap_process_otpLogin` function, where a loose PHP comparison operator is used to validate OTP codes. This weakness allows unauthenticated attackers to bypass the OTP verification process and log in as any user with a verified email address, potentially gaining administrative access. Successful exploitation requires the attacker to submit the string "true" as the OTP value. This vulnerability poses a significant risk to WordPress sites using the affected plugin, potentially leading to complete site compromise.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using a vulnerable version of the User Verification by PickPlugins plugin (<= 2.0.46).
2.  The attacker navigates to the OTP login form provided by the plugin.
3.  The attacker enters the email address of a target user, such as an administrator.
4.  The attacker intercepts the OTP request and instead of a numerical code, submits the string "true" as the OTP value.
5.  The vulnerable `user_verification_form_wrap_process_otpLogin` function processes the submitted OTP. Due to the loose PHP comparison (e.g., `==` instead of `===`), the string "true" evaluates to `true`, bypassing the intended OTP validation.
6.  The plugin incorrectly authenticates the attacker as the targeted user.
7.  The attacker gains unauthorized access to the targeted user's account, potentially gaining administrative privileges.
8.  The attacker can now perform actions such as modifying website content, installing malicious plugins, or exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-7458 allows unauthenticated attackers to bypass the OTP verification mechanism and gain unauthorized access to any user account with a verified email address on a vulnerable WordPress site. This can lead to complete compromise of the affected WordPress site, enabling attackers to modify content, inject malicious code, steal sensitive data, or use the site for malicious purposes. Given the plugin's popularity, this vulnerability could impact a large number of WordPress websites.

## Recommendation

*   Upgrade the User Verification by PickPlugins plugin to the latest version (greater than 2.0.46) to patch CVE-2026-7458.
*   Monitor WordPress access logs for unusual login attempts or the presence of "true" as OTP values to identify potential exploitation attempts. Deploy the `Detect Successful Authentication Bypass via True OTP` Sigma rule.
*   Implement stricter input validation and sanitization for OTP codes to prevent similar bypass vulnerabilities.
