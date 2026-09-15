---
title: Privilege Escalation in Consulting Theme for WordPress via Improper Access Control
slug: 2026-09-consulting-theme-privilege-escalation
description: The Consulting theme for WordPress in versions 6.7.16 and earlier contains a vulnerability allowing authenticated users to escalate privileges to administrator by manipulating insecure transient-based authentication mechanisms.
date: "2026-09-15T13:41:01Z"
lastmod: "2026-09-15T15:31:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:stylemixthemes:consulting:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-14805&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - web-application
  - privilege-escalation
vendors:
  - StylemixThemes
products:
  - Consulting (<= 6.7.16)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Consulting theme for WordPress is vulnerable to Privilege Escalation in versions up to, and including, 6.7.16.
    confidence_band: high
cves:
  - id: CVE-2026-14805
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14805
  - https://sploitus.com/exploit?id=CVE-2026-14805&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-14805 Exploitation - Unauthorized Transient Modification
    description: Detects exploitation attempts targeting the masterstudy_ms_stm_set_discard_transient AJAX endpoint used for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update Consulting theme to a patched version beyond 6.7.16
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-14805 advisory
  hunt_leads:
    - lead: Search web logs for action=masterstudy_ms_stm_set_discard_transient
      technique_id: T1068
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes exploitation via this AJAX endpoint
  mitigation_plan:
    - priority: immediate
      action: Update Consulting theme
      owner: IT Operations
      addresses: CVE-2026-14805
      evidence: NVD advisory
updates:
  - at: "2026-09-15T15:31:06Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-14805&utm_source=rss&utm_medium=rss
---

The Consulting theme for WordPress (up to and including version 6.7.16) is susceptible to privilege escalation due to insecure implementation of AJAX endpoints and developer access login mechanisms. The vulnerability stems from two primary issues in the theme's codebase: the `masterstudy_ms_stm_set_discard_transient` AJAX action in `admin/admin-notices/classes/STMHandler.php` lacks capability checks and nonce validation, and the login logic in `admin/classes/stm-theme-support.php` relies on a transient value for authentication that can be bypassed if the site is in legacy string mode. An attacker with minimal subscriber-level access can set the `stm_developer_access_token` transient to a known value and subsequently trigger the authentication mechanism to impersonate any user, including administrators. This allows for full administrative access to the WordPress site.

## Attack Chain

1. Attacker obtains a standard subscriber-level account on the target WordPress site.
2. Attacker crafts a request to the `masterstudy_ms_stm_set_discard_transient` AJAX endpoint.
3. Attacker injects a value for the `stm_developer_access_token` transient via the unprotected endpoint.
4. Attacker navigates to the endpoint handled by `admin/classes/stm-theme-support.php`.
5. The application validates the transient value as a sufficient condition for authentication in legacy mode.
6. Attacker is granted a session as the target user.
7. Attacker performs administrative actions, such as installing malicious plugins or modifying site configuration.

## Impact

Successful exploitation grants a low-privileged attacker full administrative control over the affected WordPress environment. This impact includes the potential for arbitrary code execution, sensitive data exfiltration, and full site takeover.

## Recommendation

Prioritized actions for security teams:
- Update the Consulting WordPress theme to the latest patched version immediately.
- Review WordPress access logs for anomalous requests to the `admin-ajax.php` endpoint containing `masterstudy_ms_stm_set_discard_transient`.
- Audit subscriber-level accounts for recent unauthorized activities or changes made to high-privilege user profiles.
- Monitor for requests targeting `stm-theme-support.php` paths within the web server logs.
