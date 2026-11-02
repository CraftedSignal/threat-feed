---
brief_id: brief-2026-11-02-woocommerce-plugin-privilege-escalation
event_id: brief-2026-11-02-woocommerce-plugin-privilege-escalation
revision: 1
activity_at: "2026-11-02T15:48:22Z"
title: 'Product Gallery Slider & Additional Variation Images for WooCommerce: Privilege Escalation (CVE-2026-120318)'
slug: 2026-11-woocommerce-plugin-privilege-escalation
description: An improper authorization vulnerability in the Codestar framework integration within the Product Gallery Slider & Additional Variation Images for WooCommerce plugin allows Shop Managers to escalate privileges to administrator via arbitrary WordPress option modification.
date: "2026-11-02T15:48:22Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against NVD source material.
cpes:
  - cpe:2.3:a:codestar:product_gallery_slider_&_additional_variation_images_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - Codestar
products:
  - Product Gallery Slider & Additional Variation Images for WooCommerce (< 2.3.26)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Shop Managers can read the csf_backup_nonce from the settings page and supply arbitrary option names via the 'unique' parameter to read, overwrite or delete WordPress options, including modifying wp_user_roles to escalate to administrator.
    confidence_band: high
cves:
  - id: CVE-2026-120318
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120318
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Product Gallery Slider & Additional Variation Images for WooCommerce to 2.3.26 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-120318 vulnerability advisory
  hunt_leads:
    - lead: Monitor WordPress AJAX request logs for calls to csf-export, csf-import, or csf-reset by users with the Shop Manager role.
      technique_id: T1068
      data_needed:
        - Web server access logs or WordPress audit logs (e.g., WP Security Audit Log)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggered via Codestar backup AJAX actions csf-export, csf-import and csf-reset.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Product Gallery Slider & Additional Variation Images for WooCommerce to 2.3.26 or later.
      owner: IT Operations
      addresses: CVE-2026-120318
      evidence: Source advisory specifies 2.3.26 as the patched version.
---

The Product Gallery Slider & Additional Variation Images for WooCommerce plugin (versions prior to 2.3.26) contains a missing authorization vulnerability in the Codestar framework (CSF) component. Authenticated users with the Shop Manager role can access specific AJAX actions (`csf-export`, `csf-import`, `csf-reset`). By obtaining the `csf_backup_nonce` from the settings page, these users can interact with these actions to manipulate arbitrary WordPress options. An attacker can overwrite the `wp_user_roles` option, effectively granting themselves administrative privileges.

## Impact
Successful exploitation allows a Shop Manager to escalate their privileges to administrator. This provides full control over the WordPress instance, including the ability to install plugins, modify site content, and access sensitive database information.

## Recommendation
- Update the "Product Gallery Slider & Additional Variation Images for WooCommerce" plugin to version 2.3.26 or later immediately.
- Audit WordPress user roles to identify any accounts with unexpected administrative permissions.
- Audit WordPress site options for unauthorized modifications, particularly the `wp_user_roles` option.
