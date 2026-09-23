---
title: Authentication Bypass in EthPress WordPress Plugin
slug: 2026-09-ethpress-auth-bypass
description: CVE-2026-19125 allows unauthenticated attackers to bypass authentication in the EthPress WordPress plugin (v2.3.5 and below) by supplying malformed signatures to impersonate any user with a linked Ethereum wallet.
date: "2026-09-23T14:55:42Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - wordpress
  - authentication-bypass
  - cve-2026-19125
products:
  - EthPress (< 2.3.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can supply a malicious or empty signature to the authentication mechanism, allowing them to impersonate any user.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: Successful exploitation grants the attacker a valid session cookie and administrative access to the WordPress site.
    confidence_band: high
rules:
  - title: Detect CVE-2026-19125 Exploitation - EthPress Auth Bypass
    description: Detects exploitation attempts against the EthPress plugin where unauthenticated sessions are established via malformed signature verification.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade EthPress to version 2.3.6 or later.
      owner: IT Operations
      due: 24h
      evidence: Source remediation section.
  hunt_leads:
    - lead: Search logs for unusual volume of requests to admin-ajax.php with action=ethpress_log_in.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC automation capabilities.
  mitigation_plan:
    - priority: immediate
      action: Disable the EthPress plugin if immediate upgrading is not possible.
      owner: IT Operations
      addresses: CVE-2026-19125
      evidence: Remediation section.
---

CVE-2026-19125 is an authentication bypass vulnerability affecting the EthPress WordPress plugin, versions 2.3.5 and earlier. The vulnerability exists within the plugin's wallet-based login mechanism, specifically in the `Address::log_in()` function and related cryptographic signature verification logic. An unauthenticated attacker can exploit this by providing a malformed or empty signature, which the plugin fails to validate correctly.

By supplying an Ethereum wallet address that is already linked to a target WordPress user's account, an attacker can trick the system into authenticating as that user, including accounts with administrative privileges. Once the session cookie is issued, the attacker gains full access to the WordPress site's administrative functions. The flaw was disclosed alongside a functional proof-of-concept (PoC) that automates nonce harvesting, authentication bypass, and session validation. Defenders should identify exposed WordPress instances running EthPress and prioritize upgrading to version 2.3.6 or later.

## Attack Chain

1. The attacker performs an initial GET request to `/wp-login.php` to extract the `ethpressLoginWP.loginNonce` from the site's HTML.
2. The attacker crafts a request to the plugin's AJAX endpoint, supplying a target WordPress user's linked wallet address and an empty or malformed cryptographic signature.
3. The plugin's `Address::log_in()` function fails to properly verify the signature integrity but proceeds to resolve the wallet address to the corresponding `uid` in the WordPress database.
4. The plugin invokes `wp_set_auth_cookie()` using the resolved `uid`, granting the attacker a session cookie for the targeted user.
5. The attacker uses the returned session cookie to browse to the WordPress administrative dashboard.
6. The attacker leverages the session to access privileged areas, such as `/wp/v2/users/me` or other administrative REST API endpoints, confirming full site control.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized administrative access to WordPress sites running the vulnerable EthPress plugin. This impact includes the potential for complete site compromise, data exfiltration, and the creation of additional persistence mechanisms, such as new administrative users or injected malicious code. The vulnerability is highly severe for any enterprise or individual using EthPress, as it leverages pre-existing wallet links to bypass standard authentication entirely.

## Recommendation

* Upgrade the EthPress plugin to version 2.3.6 or newer immediately. There is no configuration-based workaround for this vulnerability.
* Audit WordPress `wp_usermeta` tables for the `ethpress` meta_key to identify which accounts have linked wallet addresses and prioritize securing these high-value targets.
* Implement the following web server-level detection to identify exploitation attempts targeting the plugin's authentication endpoint.
