---
title: CVE-2026-9273 Password Reset Poisoning in Kadence Memberships
slug: 2026-08-kadence-memberships-poisoning
description: The Kadence Memberships plugin for WordPress is vulnerable to password reset link poisoning, allowing unauthenticated attackers to hijack accounts by redirecting users to malicious hosts to harvest reset tokens.
date: "2026-08-05T08:05:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - account-takeover
  - wordpress
  - cve-2026-9273
vendors:
  - Kadence
products:
  - Membership Plugin - Kadence Memberships (<= 4.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This makes it possible for unauthenticated attackers to issue a password-reset request for any account... leading to account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-9273
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9273
rules:
  - title: Detect CVE-2026-9273 Exploitation - Suspicious rc_redirect Parameter
    description: Detects exploitation of CVE-2026-9273 by identifying POST requests to the site where the rc_redirect parameter contains an external or suspicious domain indicator
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update Kadence Memberships plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-9273 patch availability
  hunt_leads:
    - lead: Search web logs for POST requests containing rc_redirect=http
      technique_id: T1555
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability analysis indicates rc_redirect is a sink for external URL injection
  mitigation_plan:
    - priority: immediate
      action: WAF blocking of requests with rc_redirect parameters pointing to non-internal domains
      owner: IT Operations
      addresses: CVE-2026-9273
      evidence: Source documentation of insecure input validation
---

The Membership Plugin - Kadence Memberships plugin for WordPress (all versions up to and including 4.0.0) contains a critical vulnerability related to improper input validation in its legacy lost-password handler. The handler, `rc_process_lost_password_form()`, improperly trusts the user-supplied `rc_redirect` POST parameter. Attackers can leverage this to inject arbitrary URLs into the password reset process. Because the necessary nonce for the reset request is available to any anonymous visitor via the `[login_form]` shortcode, unauthenticated attackers can craft requests that direct victims to an external, attacker-controlled domain. When a victim clicks the malicious link, the sensitive reset token is leaked to the attacker's server. The attacker can then use this token on the legitimate WordPress site to reset the password and achieve account takeover, including for administrative accounts. This issue presents a high risk due to the ease of exploitation and the potential for full site compromise.

## Attack Chain

1. Attacker visits a public page on the target WordPress site to obtain a valid nonce from the rendered `[login_form]` shortcode.
2. Attacker identifies the target user account, such as an administrator, to initiate a password reset.
3. Attacker crafts a malicious HTTP POST request to the legacy lost-password handler endpoint.
4. The request includes the harvested nonce and a malicious `rc_redirect` parameter pointing to an attacker-controlled host.
5. The plugin processes the request and generates a password reset email containing a link that redirects the victim to the attacker's server.
6. The victim receives and clicks the password reset link, inadvertently sending the reset key and login information to the attacker's controlled host.
7. Attacker captures the reset key from their server logs.
8. Attacker uses the leaked key to complete the password reset flow on the legitimate site, gaining control over the victim's account.

## Impact

Successful exploitation allows unauthenticated attackers to perform unauthorized account takeovers. This impact is significant as it includes administrative accounts, potentially leading to full site compromise, sensitive data exfiltration, and the execution of arbitrary code via administrative plugin or theme installation capabilities within WordPress.

## Recommendation

* Update the Kadence Memberships plugin to a version addressing CVE-2026-9273 immediately.
* Monitor web server logs for suspicious POST requests targeting legacy password reset endpoints or those containing unexpected `rc_redirect` parameters pointing to external domains.
* Deploy web application firewall (WAF) rules to validate or block the `rc_redirect` parameter if it contains non-local or non-whitelisted domain components.
