---
brief_id: brief-2026-10-29-woo-telegram-auth-bypass
event_id: brief-2026-10-29-woo-telegram-auth-bypass
revision: 1
activity_at: "2026-10-29T05:02:59Z"
title: 'Bot for Telegram on WooCommerce: Authentication bypass and account takeover (CVE-2026-109516)'
slug: 2026-10-woo-telegram-auth-bypass
description: The Bot for Telegram on WooCommerce plugin for WordPress is vulnerable to unauthenticated account takeover due to missing permission checks and signature validation in its REST API and authentication endpoints.
date: "2026-10-29T05:02:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:bot_for_telegram_on_woocommerce_project:bot_for_telegram_on_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Bot for Telegram on WooCommerce (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /wp-json/woo-telegram/v1/main/ REST endpoint is registered with permission_callback => '__return_true' and performs no Telegram webhook signature verification.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to log in as any WordPress user, including administrators.
    confidence_band: high
cves:
  - id: CVE-2026-109516
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109516
rules:
  - title: Detect CVE-2026-109516 Exploitation - Authentication Bypass Attempt
    description: Detects unauthorized access attempts to the Bot for Telegram on WooCommerce plugin REST endpoint, a precursor to account takeover via CVE-2026-109516.
    platform: sigma
    severity: critical
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress instances running 'Bot for Telegram on WooCommerce' <= 1.3.0 and disable the plugin
      owner: IT Operations
      due: 24h
      evidence: Plugin version 1.3.0 is vulnerable to CVE-2026-109516
  hunt_leads:
    - lead: Search web logs for successful exploitation of the bftow_create_order action
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The resulting token is redeemable at the... ?action=bftow_create_order&bftow_token= endpoint
  mitigation_plan:
    - priority: immediate
      action: Disable the plugin and check logs for signs of unauthorized administrative access
      owner: IT Operations
      addresses: CVE-2026-109516
      evidence: Plugin allows unauthenticated account takeover
---

CVE-2026-109516 affects the 'Bot for Telegram on WooCommerce' plugin for WordPress versions 1.3.0 and earlier. The plugin fails to verify Telegram webhook signatures and incorrectly trusts attacker-supplied input within its REST API and order creation actions, leading to full authentication bypass and privilege escalation.

## Attack Chain

1. Attacker sends a forged HTTP POST request to the `/wp-json/woo-telegram/v1/main/` endpoint.
2. The endpoint, lacking a permission callback, accepts the request.
3. The attacker provides a `message.chat.id` field set to the target user's login username.
4. The `bftow_get_user_system_id()` function retrieves the victim's user ID via `get_user_by('login', $tgId)` without proof of identity.
5. The attacker calculates a session token based on their `User-Agent` and the current `time()`.
6. The attacker invokes the `?action=bftow_create_order&bftow_token=` endpoint with the crafted token.
7. The plugin calls `wp_set_auth_cookie()` using the victim's ID, granting the attacker a persistent authenticated session.

## Impact

Successful exploitation allows unauthenticated attackers to gain persistent administrative access to the WordPress site, enabling full account takeover.

## Recommendation

1. Disable or uninstall the 'Bot for Telegram on WooCommerce' plugin immediately if not currently using a patched version.
2. Review web server access logs for anomalous POST requests to `/wp-json/woo-telegram/v1/main/` and GET/POST requests containing `action=bftow_create_order`.
3. Audit WordPress user accounts for suspicious activities or unauthorized password/email changes occurring after the deployment of the vulnerable plugin version.
