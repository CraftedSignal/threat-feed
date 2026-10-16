---
title: Unauthenticated Privilege Escalation in MailOptin WordPress Plugin
slug: 2026-10-mailoptin-priv-esc
description: The MailOptin WordPress plugin contains a vulnerability in the subscribe_to_email_list endpoint that allows unauthenticated attackers to overwrite arbitrary user accounts, including administrators, via insecure parameter handling.
date: "2026-10-16T06:24:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mailoptin:mailoptin:*:*:*:*:*:wordpress:*:*
vendors:
  - MailOptin
products:
  - MailOptin (<= 1.2.78.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to force wp_insert_user() into UPDATE mode on any existing account by supplying a target user's numeric ID, overwrite that account's password with a pre-hashed value of their choosing, and thereby take over any WordPress user account.
    confidence_band: high
cves:
  - id: CVE-2026-109515
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109515
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade MailOptin plugin to the latest version patched against CVE-2026-109515
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Remove or disable public-facing MailOptin registration forms
      owner: IT Operations
      addresses: CVE-2026-109515
      evidence: NVD vulnerability disclosure
---

The MailOptin plugin for WordPress (versions 1.2.78.6 and below) is vulnerable to a critical privilege escalation flaw. The vulnerability resides in the `subscribe_to_email_list` endpoint, which fails to validate the `optin_data[form_custom_field_mappings]` parameter. This oversight allows an unauthenticated attacker to inject arbitrary user database column names into the `wp_insert_user()` function. By passing an existing administrator's user ID and a chosen password, an attacker can force an update to an existing account. This mechanism enables complete site compromise without requiring prior authentication, nonce validation, or specific user capabilities. Successful exploitation requires an active WordPress User Registration opt-in form, which is typically exposed in the public page source.

## Attack Chain

1. Attacker identifies a site running the MailOptin plugin and scans public pages to retrieve the form UUID.
2. Attacker interacts with the `subscribe_to_email_list` endpoint without authentication.
3. Attacker crafts a malicious POST request containing the `optin_data[form_custom_field_mappings]` parameter.
4. The input is passed to the `subscribe()` function, bypassing validation checks.
5. The attacker-supplied mappings override internal configurations, including `ID` and `user_pass` fields.
6. The `wp_insert_user()` function is invoked with the injected, attacker-controlled parameters.
7. The WordPress database record for the targeted user ID is updated with the attacker-provided password.
8. Attacker logs into the WordPress administrative panel using the compromised account credentials.

## Impact

Successful exploitation leads to full site takeover by granting attackers administrative access to WordPress instances. Given the widespread use of WordPress opt-in and newsletter plugins, this vulnerability affects any site with a publicly visible registration opt-in form configured via the affected versions of MailOptin. Unauthorized administrative access allows for the deployment of backdoors, data exfiltration, and full control over site content and configuration.

## Recommendation

* Immediately update the MailOptin plugin to a version released after 1.2.78.6 to patch the insecure parameter validation.
* Audit WordPress user account logs for suspicious password resets or unexpected account updates occurring via the `wp_insert_user` context.
* Disable public-facing opt-in forms on WordPress installations until the patch is applied.
