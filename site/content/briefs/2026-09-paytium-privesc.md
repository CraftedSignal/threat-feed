---
title: Privilege Escalation in Paytium WordPress Plugin via Improper Meta Handling
slug: 2026-09-paytium-privesc
description: 'The Paytium: Mollie payment forms & donations plugin for WordPress contains an unauthenticated privilege escalation vulnerability allowing attackers to register as site administrators.'
date: "2026-09-24T02:45:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:paytium:paytium_mollie_payment_forms_donations:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - privilege-escalation
vendors:
  - Paytium
products:
  - 'Paytium: Mollie payment forms & donations (<= 5.0.3)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to register a new WordPress account with the administrator role and fully take over the site.
    confidence_band: high
cves:
  - id: CVE-2026-18467
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18467
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: 'Upgrade Paytium: Mollie payment forms & donations plugin to the latest available version.'
      owner: IT Operations
      due: 24h
      evidence: Source document indicates version 5.0.3 and earlier are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: 'Upgrade Paytium: Mollie payment forms & donations to a version patched beyond 5.0.3.'
      owner: IT Operations
      addresses: CVE-2026-18467
      evidence: NVD vulnerability disclosure.
---

The Paytium: Mollie payment forms & donations plugin for WordPress (versions 5.0.3 and below) is susceptible to a critical privilege escalation vulnerability. Although the 5.0.3 patch implemented signature verification on the pt-paytium-user-data field, it failed to apply the same rigor to the pt_cf_checkout_meta function. This function, registered on the pt_meta_values hook, allows attackers to inject arbitrary keys from the $_POST['pt_form_field'] array into the payment meta array. An attacker can supply a pt-user-role key, which subsequently overwrites the legitimate data processed by the plugin. When paytium_user_data_processing is invoked, it reads this unauthorized meta and passes the value directly into the wp_insert_user function. This flaw allows an unauthenticated visitor to register a new account on a site and force the system to assign it the 'administrator' role, leading to full site compromise.

## Impact

Successful exploitation allows unauthenticated attackers to elevate their privileges to the administrator level, granting them complete control over the affected WordPress installation. This enables the theft of site data, installation of malicious backdoors, and total administrative takeover of the targeted website.

## Recommendation

1. Immediately upgrade the Paytium: Mollie payment forms & donations plugin to a version patched beyond 5.0.3.
2. Audit existing WordPress user accounts for suspicious administrators created or modified recently.
3. Monitor web server logs for POST requests targeting [paytium] shortcode form submission endpoints that include unexpected role-related metadata parameters.
