---
brief_id: brief-2026-11-09-mail-debug-woocommerce-vuln
event_id: brief-2026-11-09-mail-debug-woocommerce-vuln
revision: 1
activity_at: "2026-11-09T15:51:14Z"
title: 'Mail Debug for WooCommerce: Unauthenticated email exposure (CVE-2026-115256)'
slug: 2026-11-mail-debug-woocommerce-vuln
description: The Mail Debug for WooCommerce WordPress plugin up to version 1.3.0 contains an unauthenticated access vulnerability that allows attackers to read site email logs, including password reset links.
date: "2026-11-09T15:51:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:mail_debug_for_woocommerce_project:mail_debug_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
products:
  - Mail Debug for WooCommerce (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: allowing anyone to read the full body of every email the site has sent, including password-reset emails whose reset key lets an attacker take over an administrator account.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: is exposed to unauthenticated users and is not restricted to its own data, allowing anyone to read the full body of every email
    confidence_band: high
cves:
  - id: CVE-2026-115256
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115256
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit WordPress plugin inventory to identify active installations of Mail Debug for WooCommerce
      owner: IT Operations
      due: 24h
      evidence: Vulnerability impacts versions through 1.3.0
  hunt_leads:
    - lead: Monitor web server access logs for anomalous requests to the plugin email-logging endpoint
      technique_id: T1190
      data_needed:
        - web server access logs (cs-uri-stem, cs-method)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The flaw is exposed via an unauthenticated email-logging action in the plugin.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove Mail Debug for WooCommerce until a patched version is available
      owner: IT Operations
      addresses: CVE-2026-115256
      evidence: Plugin lacks authentication, capability, and nonce checks
---

The Mail Debug for WooCommerce plugin contains a vulnerability in an email-logging function that lacks proper capability, authentication, and nonce checks. This flaw allows unauthenticated remote attackers to query the plugin's logging action to retrieve the full body of any email sent by the WordPress site. The exposure of password reset emails containing reset tokens facilitates full administrative account takeover. No patch or fixed version information is currently disclosed in the source.

## Impact

Successful exploitation allows unauthenticated attackers to read all outgoing site emails. The primary impact is the unauthorized capture of sensitive data, specifically password reset tokens, which permits full account compromise of administrative users.

## Recommendation

- Identify all WordPress instances running the "Mail Debug for WooCommerce" plugin.
- Disable or remove the plugin until a patch is released by the vendor, as there are no authentication controls to mitigate this risk.
- Review WordPress email logs or audit logs for unusual GET or POST requests directed at plugin-specific endpoints associated with email debugging.
- Reset all user credentials for administrative accounts if the site is known to have been exposed to external traffic while running vulnerable versions of this plugin.
