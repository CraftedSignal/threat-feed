---
title: Authentication Bypass in Advanced Responsive Video Embedder WordPress Plugin
slug: 2026-07-wordpress-arve-bypass
description: A critical authentication bypass vulnerability, CVE-2026-18072, affects version 10.8.7 of the Advanced Responsive Video Embedder for Rumble, Odysee, YouTube, Vimeo, Kick … plugin for WordPress, allowing unauthenticated attackers to gain full administrative control by supplying a hardcoded token via the `_wplogin` or `_wpm` URL parameter.
date: "2026-07-29T05:21:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authentication-bypass
  - web-vulnerability
products:
  - Advanced Responsive Video Embedder for Rumble, Odysee, YouTube, Vimeo, Kick … plugin (10.8.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Advanced Responsive Video Embedder for Rumble, Odysee, YouTube, Vimeo, Kick … plugin for WordPress is vulnerable to Authentication Bypass via a Hardcoded Backdoor in version 10.8.7.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: unauthenticated attackers can supply the known token to be authenticated as an arbitrarily selected existing administrator account, gaining full administrative control over the affected WordPress site.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: unauthenticated attackers can supply the known token to be authenticated as an arbitrarily selected existing administrator account, gaining full administrative control over the affected WordPress site.
    confidence_band: high
cves:
  - id: CVE-2026-18072
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18072
rules:
  - title: Detects CVE-2026-18072 Exploitation - Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2026-18072 by looking for the `_wplogin` or `_wpm` parameters in HTTP requests, which are used to trigger the hardcoded backdoor in the Advanced Responsive Video Embedder WordPress plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-18072 identifies a critical authentication bypass vulnerability in version 10.8.7 of the Advanced Responsive Video Embedder for Rumble, Odysee, YouTube, Vimeo, Kick … plugin for WordPress. This flaw arises from a hardcoded backdoor within the `_arve_uc_init()` function, which is registered on WordPress's `init` hook with priority 1, ensuring it executes before standard authentication checks. Unauthenticated attackers can exploit this by supplying a specific, hardcoded SHA-256 token via the `_wplogin` or `_wpm` URL parameter. The function compares the provided token against the static hash embedded directly in the plugin's source code, completely bypassing nonce verification, capability checks, and password validation. This allows attackers to authenticate as any existing administrator account, thereby achieving full administrative control over the affected WordPress site. The presence of this backdoor suggests it may have been maliciously introduced by an attacker who gained commit access to the plugin developers' account.

## Attack Chain

1. Attacker identifies a target WordPress site running the Advanced Responsive Video Embedder plugin version 10.8.7.
2. Attacker obtains the publicly known hardcoded SHA-256 hash (acting as universal credentials) from the plugin's source code.
3. Attacker crafts an HTTP GET or POST request targeting the vulnerable WordPress instance.
4. The request includes a URL query parameter, either `_wplogin` or `_wpm`, containing the hardcoded SHA-256 token.
5. The WordPress `init` hook triggers the `_arve_uc_init()` function, which processes the attacker-supplied token from the URL parameter.
6. The `_arve_uc_init()` function validates the provided token against the internally hardcoded SHA-256 hash, bypassing all legitimate authentication mechanisms.
7. The attacker is successfully authenticated as an arbitrarily selected existing administrator account on the WordPress site without needing valid credentials.
8. Attacker gains full administrative control, enabling actions such as content modification, plugin/theme installation, data exfiltration, or further compromise of the web server.

## Impact

Successful exploitation of CVE-2026-18072 grants unauthenticated attackers full administrative control over the affected WordPress site. This can lead to severe consequences including, but not limited to, complete website defacement, arbitrary code execution, exfiltration of sensitive data, creation of new malicious administrator accounts for persistence, and the use of the compromised site as a platform for further attacks (e.g., malware distribution, phishing campaigns). The exact number of victims is not specified, but any organization utilizing the vulnerable plugin version is at critical risk.

## Recommendation

* **Patch CVE-2026-18072 immediately** by updating the "Advanced Responsive Video Embedder for Rumble, Odysee, YouTube, Vimeo, Kick …" plugin to a version greater than 10.8.7.
* **Deploy the Sigma rule below** to your SIEM to detect exploitation attempts of CVE-2026-18072, ensuring webserver logs are collected.
* **Review webserver access logs** for the presence of `_wplogin` or `_wpm` query parameters, as indicated in the Sigma rule.
