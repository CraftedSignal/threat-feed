---
title: Unauthenticated Privilege Escalation in SimpleForm WordPress Plugin
slug: 2026-10-simpleform-privilege-escalation
description: The SimpleForm plugin for WordPress (<= 3.10.0) is vulnerable to unauthenticated administrator account creation due to missing capability checks on the wp_ajax_nopriv_simpleform_wp_register AJAX action.
date: "2026-10-14T08:23:08Z"
lastmod: "2026-10-14T11:47:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:simpleform_project:simpleform:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=068D2F9E-11A4-556A-BFFA-091E8EEF1B9E&utm_source=rss&utm_medium=rss
vendors:
  - WordPress
products:
  - SimpleForm – Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications (<= 3.10.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: Abuse Elevation Control Mechanism
    evidence: This makes it possible for unauthenticated attackers to create a new Administrator-level WordPress account by supplying wp_capabilities[administrator]=1
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: An unauthenticated attacker can exploit this... to create a new Administrator account
    confidence_band: high
cves:
  - id: CVE-2026-104748
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104748
  - https://sploitus.com/exploit?id=068D2F9E-11A4-556A-BFFA-091E8EEF1B9E&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-104748 Exploitation - Unauthorized Admin Account Creation
    description: Detects exploitation attempts by identifying POST requests to admin-ajax.php containing the simpleform registration action and user capability injection attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update SimpleForm to a version beyond 3.10.0.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable <= 3.10.0
    - action: Deploy Sigma detection rule.
      owner: Detection Engineering
      due: 24h
      evidence: Rule defined in brief
  mitigation_plan:
    - priority: immediate
      action: Upgrade SimpleForm plugin to version > 3.10.0.
      owner: IT Operations
      addresses: CVE-2026-104748
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-14T11:47:54Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=068D2F9E-11A4-556A-BFFA-091E8EEF1B9E&utm_source=rss&utm_medium=rss
---

The SimpleForm - Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications plugin for WordPress, in versions up to and including 3.10.0, contains a critical privilege escalation vulnerability. The `wp_ajax_nopriv_simpleform_wp_register` AJAX action fails to perform capability validation for role assignment during user registration. Furthermore, the `save_custom_fields_to_user_meta()` function improperly excludes user meta fields, failing to filter `wp_capabilities`. 

Because `get_form_settings()` returns a hard-coded defaults array that enables meta writing, an unauthenticated attacker can supply `wp_capabilities[administrator]=1` within registration requests. The nonce required for this action is exposed in the `front_end_data` JavaScript object, which is publicly accessible to any site visitor. This flaw allows attackers to bypass registration controls and gain full administrative access to affected WordPress instances.

## Impact

Successful exploitation grants an unauthenticated attacker full administrative privileges on the target WordPress site. This leads to complete site compromise, including the ability to execute arbitrary PHP code, modify site content, access sensitive database information, and pivot to the underlying host or associated infrastructure.

## Recommendation

* Immediately update the SimpleForm plugin to a version beyond 3.10.0.
* Audit WordPress user lists for unauthorized administrator accounts, specifically looking for accounts created recently via the SimpleForm registration flow.
* Monitor web server access logs for anomalous POST requests directed toward `/wp-admin/admin-ajax.php` containing the `action=simpleform_wp_register` parameter, specifically inspecting payloads for `wp_capabilities` fields.
