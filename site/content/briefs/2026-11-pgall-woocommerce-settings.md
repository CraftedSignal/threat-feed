---
brief_id: brief-2026-11-07-pgall-woocommerce-settings
event_id: brief-2026-11-07-pgall-woocommerce-settings
revision: 1
activity_at: "2026-11-07T15:58:32Z"
title: 'PGALL for WooCommerce: Unauthenticated settings change (CVE-2026-95597)'
slug: 2026-11-pgall-woocommerce-settings
description: An unauthenticated settings change vulnerability in the PGALL for WooCommerce plugin allows attackers to manipulate payment gateway configurations via AJAX by harvesting nonces from public checkout pages.
date: "2026-11-07T15:58:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - cpe:2.3:a:pgall_for_woocommerce_project:pgall_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - PGALL for WooCommerce (<= 5.5.17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The plugin registers the AJAX action pgall-for-woocommerce-pafw_ajax_action for logged out visitors.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: The attacker leverages a shell-based proof of concept (poc.sh) to execute the unauthorized settings change.
    confidence_band: high
cves:
  - id: CVE-2026-95597
    cvss: 6.5
    epss: 0.00242
    kev_status: "false"
references:
  - https://patchstack.com/database/wordpress/plugin/pgall-for-woocommerce/vulnerability/wordpress-plugin-5-5-17-settings-change-vulnerability
  - https://mor-golan.github.io/research/cve-2026-95597-pgall-for-woocommerce
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-95597
  - https://sploitus.com/exploit?id=12B53371-AB33-5A57-8D86-17901E4BD038&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-95597 Exploitation - Unauthenticated AJAX Action
    description: Detects exploitation attempts against PGALL for WooCommerce by monitoring POST requests to admin-ajax.php involving the vulnerable AJAX action.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Update PGALL for WooCommerce to 5.5.18 or later
      owner: IT Operations
      due: 24h
      evidence: Fixed in version 5.5.18
  hunt_leads:
    - lead: Review web server logs for high frequency of POST requests to admin-ajax.php with action=pgall-for-woocommerce-pafw_ajax_action
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The handler is exposed to logged out users and requires only a nonce available on public pages.
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rule to block unauthorized admin-ajax.php requests
      owner: IT Operations
      addresses: CVE-2026-95597
      evidence: Unauthenticated settings change vulnerability
---

The PGALL for WooCommerce WordPress plugin contains a vulnerability (CVE-2026-95597) that enables unauthenticated users to change plugin settings. The vulnerability exists within the AJAX handler `pgall-for-woocommerce-pafw_ajax_action`, which is exposed to logged-out users. The handler lacks proper capability checks or allow-listing for the methods it executes. Attackers can obtain the required nonce from the public WooCommerce checkout page and subsequently invoke methods such as `save_account_details` or `process_admin_options` to modify payment gateway configurations, including bank account details.

## Attack Chain
1. Attacker visits the public shop page to discover a product.
2. Attacker adds the product to the cart to establish an anonymous WooCommerce session.
3. Attacker navigates to the public checkout page to harvest the `_pafw._wpnonce`.
4. Attacker crafts a POST request to `/wp-admin/admin-ajax.php`.
5. Attacker provides the harvested nonce along with parameters `payment_method=bacs` and `payment_action=save_account_details`.
6. The plugin handler executes the payment gateway method without authorization.
7. The merchant's bank account details are overwritten with attacker-controlled data.

## Impact
Successful exploitation allows unauthenticated attackers to modify critical store payment settings. This can lead to financial fraud by redirecting customer payments to attacker-controlled bank accounts and disrupting site availability by disabling payment gateways.

## Recommendation
- Update the PGALL for WooCommerce plugin to version 5.5.18 or later immediately.
- Review current payment gateway configurations for unauthorized changes to bank details or gateway status.
- Implement Web Application Firewall (WAF) rules to inspect and filter POST requests to `admin-ajax.php` containing `pgall-for-woocommerce-pafw_ajax_action` from unauthenticated or suspicious IP addresses.
