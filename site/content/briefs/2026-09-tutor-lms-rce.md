---
title: PHP Object Injection in Tutor LMS Plugin for WordPress
slug: 2026-09-tutor-lms-rce
description: Tutor LMS plugin versions up to 4.0.7 are vulnerable to remote code execution via PHP object injection in the tutor_save_withdraw_account AJAX handler, allowing attackers to leverage POP chains.
date: "2026-09-12T09:19:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:themeum:tutor_lms:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - rce
  - php-injection
  - vulnerability
vendors:
  - Themeum
products:
  - Tutor LMS (<= 4.0.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated attacker, with subscriber-level access and above, to achieve remote code execution on the server.
    confidence_band: high
cves:
  - id: CVE-2026-78175
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78175
rules:
  - title: Detect Exploitation of CVE-2026-78175 in Tutor LMS
    description: Detects HTTP POST requests targeting the tutor_save_withdraw_account AJAX action, which is the vector for CVE-2026-78175
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update Tutor LMS to 4.0.8 or later
      owner: IT Operations
      due: 24h
      evidence: Plugin version 4.0.7 is vulnerable per NVD
  mitigation_plan:
    - priority: immediate
      action: Disable monetization feature and public registration if not required
      owner: IT Operations
      addresses: CVE-2026-78175
      evidence: Vulnerability requires monetization feature to be enabled
---

Tutor LMS, a popular eLearning solution for WordPress, contains a critical vulnerability (CVE-2026-78175) affecting all versions up to and including 4.0.7. The vulnerability exists within the 'tutor_save_withdraw_account' AJAX handler, which fails to perform necessary capability or role checks. While the handler relies on a nonce, it incorrectly processes the 'withdraw_method_field' parameter by passing user-supplied input through 'esc_sql()'. This function introduces HMAC placeholders that, upon storage and subsequent retrieval, cause a discrepancy in serialized string length declarations. By providing crafted POST data, an attacker can trigger an 'unserialize()' operation on malformed data, leading to object injection. This permits the execution of a POP chain using 'GuzzleHttp\Cookie\FileCookieJar', effectively allowing an attacker to achieve remote code execution by writing arbitrary content to a file. The vulnerability is accessible to authenticated users with subscriber-level access and can be exploited by unauthenticated attackers if site registration is enabled and the monetization feature is active.

## Attack Chain

1. Attacker identifies a WordPress site running Tutor LMS <= 4.0.7 with monetization features enabled.
2. Attacker registers as a student or teacher if user registration is enabled, or uses existing low-privileged credentials.
3. Attacker crafts a malicious payload containing a serialized PHP object designed to utilize the 'GuzzleHttp\Cookie\FileCookieJar' POP chain.
4. Attacker sends an HTTP POST request to the 'wp-admin/admin-ajax.php' endpoint with the 'action' set to 'tutor_save_withdraw_account'.
5. The server-side code processes the 'withdraw_method_field' parameter, triggering the length discrepancy issue during the 'update_user_meta' operation.
6. Upon metadata retrieval, the application calls 'unserialize()' on the malformed input.
7. The deserialization process executes the POP chain, resulting in arbitrary file write capabilities.
8. Attacker writes a PHP webshell to a publicly accessible directory to achieve remote code execution.

## Impact

Successful exploitation allows unauthenticated or low-privileged attackers to achieve remote code execution on the WordPress host. This grants full control over the web application, facilitating data exfiltration, defacement, or lateral movement within the hosting environment. Thousands of WordPress installations utilizing this eLearning plugin are potentially affected if the monetization feature is configured.

## Recommendation

1. Update Tutor LMS to version 4.0.8 or later immediately to apply the patch for CVE-2026-78175.
2. Disable public user registration on WordPress sites if not strictly necessary until the update is applied.
3. Temporarily disable the monetization feature in Tutor LMS to mitigate the attack vector.
4. Review server logs for anomalous POST requests to 'admin-ajax.php' containing highly encoded or serialized-looking strings.
