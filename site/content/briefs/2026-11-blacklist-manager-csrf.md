---
brief_id: brief-2026-11-07-blacklist-manager-csrf
event_id: brief-2026-11-07-blacklist-manager-csrf
revision: 1
activity_at: "2026-11-07T17:13:47Z"
title: 'Blacklist Manager for WooCommerce: Cross-Site Request Forgery (CVE-2026-96838)'
slug: 2026-11-blacklist-manager-csrf
description: A Cross-Site Request Forgery (CSRF) vulnerability in Blacklist Manager for WooCommerce (<= 2.3.1) allows unauthenticated attackers to bypass REST API nonce checks and execute unauthorized actions, including the creation of new administrator accounts, by tricking a logged-in administrator into visiting a malicious page.
date: "2026-11-07T17:13:47Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:black_list_manager_project:black_list_manager:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Blacklist Manager for WooCommerce (<= 2.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A page I control can then drive a logged in victim browser into forging a REST request under the victim own session.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: Local Account
    evidence: Against an administrator victim a single top level navigation creates a new administrator account that I control.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: which reaches arbitrary PHP execution on the host.
    confidence_band: high
cves:
  - id: CVE-2026-96838
    cvss: 8.8
    epss: 0.00139
    kev_status: "false"
references:
  - https://patchstack.com/database/wordpress/plugin/wc-blacklist-manager/vulnerability/wordpress-blacklist-manager-8211-woocommerce-anti-fraud-blacklist-amp-checkout-verification-plugin-2-3-1-cross-site-request-forgery-csrf-vulnerability
  - https://mor-golan.github.io/research/cve-2026-96838-wc-blacklist-manager/
  - https://sploitus.com/exploit?id=EED3D265-814C-580B-9750-89E291082B91
  - https://sploitus.com/exploit?id=EED3D265-814C-580B-9750-89E291082B91&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Blacklist Manager for WooCommerce to 2.3.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2.3.2
  hunt_leads:
    - lead: Hunt for suspicious creation of new administrator accounts via WordPress REST API logs.
      technique_id: T1136.001
      data_needed:
        - WordPress access logs
        - REST API audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Against an administrator victim a single top level navigation creates a new administrator account
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to 2.3.2
      owner: IT Operations
      addresses: CVE-2026-96838
      evidence: Fixed in 2.3.2
---

Blacklist Manager for WooCommerce (<= 2.3.1) is affected by a CSRF vulnerability (CVE-2026-96838) due to an insecure implementation of the `rest_authentication_errors` filter. The plugin incorrectly discards WordPress authentication errors when a specific string is present in the request URI. This flaw effectively disables the REST nonce check for all REST routes. An attacker can craft a malicious webpage that, when visited by a logged-in administrator, executes unauthorized REST API calls, such as creating a new administrative account or executing arbitrary code.

## Attack Chain
1. Attacker identifies a target site using the vulnerable Blacklist Manager for WooCommerce plugin.
2. Attacker hosts a malicious webpage designed to trigger REST API requests against the target WordPress instance.
3. Attacker lures a logged-in WordPress administrator to the malicious page.
4. Malicious page executes a cross-origin request to the target site's WordPress REST API.
5. The vulnerable `rest_authentication_errors` filter suppresses the nonce check, authorizing the forged request under the victim's session.
6. The request succeeds, creating a new administrative user account controlled by the attacker.
7. Attacker authenticates with the newly created account to achieve arbitrary PHP execution or further system compromise.

## Impact
Successful exploitation allows for full site compromise by enabling unauthorized administrative account creation. This provides a direct path to arbitrary PHP execution and persistent backend access.

## Recommendation
- Update the Blacklist Manager for WooCommerce plugin to version 2.3.2 or later immediately.
- Audit administrative user lists for unauthorized accounts created after the vulnerability became public.
- Implement security headers and restrict administrative access to known, trusted IP ranges to mitigate the impact of potential CSRF attacks.
