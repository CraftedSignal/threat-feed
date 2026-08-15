---
title: 'Privilege Escalation in bLoyal: Loyalty & Promotions WordPress Plugin'
slug: 2026-08-bloyal-privesc
description: 'The bLoyal: Loyalty & Promotions plugin for WordPress contains an unauthenticated configuration modification and privilege escalation vulnerability, CVE-2026-15001, allowing low-privileged users to assume administrator accounts.'
date: "2026-08-15T04:16:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - bLoyal
products:
  - Loyalty & Promotions by bLoyal (3.1.611.78)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The bLoyal: Loyalty & Promotions by bLoyal plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.1.611.78.'
    confidence_band: high
cves:
  - id: CVE-2026-15001
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15001
rules:
  - title: Detect CVE-2026-15001 Exploitation Attempt
    description: Detects unauthorized attempts to save bLoyal configuration data via AJAX actions
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update bLoyal plugin to version 3.1.611.79 or higher.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 3.1.611.78
  mitigation_plan:
    - priority: immediate
      action: Patch plugin
      owner: IT Operations
      addresses: CVE-2026-15001
      evidence: NVD advisory
---

The bLoyal: Loyalty & Promotions plugin for WordPress (versions 3.1.611.78 and earlier) is susceptible to a critical privilege escalation vulnerability, tracked as CVE-2026-15001. The flaw stems from the insecure implementation of AJAX actions `save_bloyal_configuration_data` and `save_bloyal_accesskeyverification_data`, which lack necessary capability and nonce validation. Furthermore, the `bloyal_customer_auto_login` function blindly trusts the `Customer.ExternalId` returned by an API endpoint configurable within the plugin. An attacker with minimal Subscriber-level access can modify these plugin settings to point to an attacker-controlled API. By subsequently triggering the `/cart` REST route, the attacker forces the plugin to fetch a malicious user payload from their own server, leading to an unauthorized call to `wp_set_auth_cookie()` that elevates the attacker's session to that of any site user, including administrators.

## Impact

Successful exploitation results in full site compromise by granting the attacker administrator-level access. As this vulnerability affects a plugin with e-commerce and loyalty functionality, targets include any WordPress site utilizing the affected versions for customer management and promotions.

## Recommendation

- Update the bLoyal: Loyalty & Promotions plugin to the latest version immediately to remediate CVE-2026-15001.
- Audit WordPress site logs for unauthorized requests to the `/wp-admin/admin-ajax.php` endpoint containing `save_bloyal_configuration_data` or `save_bloyal_accesskeyverification_data` parameters originating from low-privileged user accounts.
- Monitor site configuration changes for unexpected modifications to the `bloyal_custom_loyaltyengine_api_url` option in the WordPress database.
