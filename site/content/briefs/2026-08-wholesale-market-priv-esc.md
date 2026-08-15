---
title: Privilege Escalation in Wholesale Market WordPress Plugin
slug: 2026-08-wholesale-market-priv-esc
description: The Wholesale Market plugin for WordPress up to version 2.2.2 contains a privilege escalation vulnerability via the ced_wholesale_request_send AJAX action that allows authenticated users to elevate to Administrator.
date: "2026-08-15T08:17:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - WordPress
products:
  - Wholesale Market
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The ced_wholesale_request_send_callback() handler... calls WP_User::add_role() with the client-supplied role_required POST parameter... possible for authenticated attackers... to elevate their privileges to Administrator.
    confidence_band: high
cves:
  - id: CVE-2026-14279
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14279
rules:
  - title: Detects CVE-2026-14279 Exploitation - Privilege Escalation via ced_wholesale_request_send
    description: Detects unauthorized usage of the ced_wholesale_request_send AJAX action where the role_required parameter contains administrative role identifiers.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy detection rule to monitor for exploitation attempts targeting the ced_wholesale_request_send action
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms plugin vulnerability in AJAX handler
  mitigation_plan:
    - priority: immediate
      action: Update Wholesale Market plugin to the latest version and verify the 'Assigning requested role directly' configuration
      owner: IT Operations
      addresses: CVE-2026-14279
      evidence: NVD vulnerability disclosure
---

The Wholesale Market plugin for WordPress, in versions up to and including 2.2.2, is susceptible to a privilege escalation vulnerability within the ced_wholesale_request_send AJAX handler. The vulnerability exists because the ced_wholesale_request_send_callback function performs inadequate security validation. Specifically, it only verifies a nonce that is exposed to any authenticated user via wp_localize_script and confirms a positive user ID. Crucially, the function fails to validate the role_required POST parameter against a secure allowlist, instead passing it directly to the WP_User::add_role() function. If the 'Assigning requested role directly' option is enabled in the plugin configuration, any authenticated attacker with at least Subscriber-level access can manipulate this parameter to assign themselves the Administrator role. This issue represents a significant risk to WordPress installations utilizing this plugin for B2B wholesale management.
