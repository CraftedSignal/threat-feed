---
title: Sensitive Information Exposure in ProfilePress Plugin
slug: 2026-10-profilepress-info-exposure
description: The ProfilePress plugin for WordPress (<= 4.17.4) is vulnerable to sensitive information exposure, allowing authenticated and unauthenticated attackers to extract user PII via crafted shortcode parameters.
date: "2026-10-03T04:53:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:profilepress:profilepress:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - wordpress
  - cve
vendors:
  - ProfilePress
products:
  - Paid Membership Plugin, Ecommerce, User Registration Form, Login Form, User Profile & Restrict Content – ProfilePress (<= 4.17.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When the WordPress users_can_register option is enabled, unauthenticated attackers can also exploit this vulnerability by supplying the split shortcode fragments through the plugin's own registration handler.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for authenticated attackers... to extract other users' email addresses, login names, and registration dates.
    confidence_band: high
cves:
  - id: CVE-2026-92536
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92536
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update ProfilePress plugin to patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92536 remediation
  mitigation_plan:
    - priority: immediate
      action: Disable 'users_can_register' setting in WordPress if patching is delayed
      owner: IT Operations
      addresses: CVE-2026-92536
      evidence: Source notes vulnerability is accessible to unauthenticated attackers if registration is enabled
---

The ProfilePress plugin for WordPress, a membership and user profile management tool, contains a critical vulnerability (CVE-2026-92536) in versions up to 4.17.4. The flaw exists within the Member Directory feature and the plugin's registration handler, specifically involving improper handling of shortcode parameters such as [pp-custom-html]. 

Authenticated attackers with subscriber-level access can manipulate the get_user_profile_structure by injecting base64-encoded payloads that utilize shortcode tags like [profile-email], [profile-username], and [profile-date-registered]. This allows for the exfiltration of sensitive user data including email addresses, login names, and registration timestamps. Furthermore, if the WordPress installation has the 'users_can_register' setting enabled, the plugin fails to enforce nonce validation on the registration handler, enabling unauthenticated attackers to trigger the same data extraction via the reg_nickname and reg_bio fields. This vulnerability poses a significant risk to user privacy and platform integrity.

## Impact

Successful exploitation of CVE-2026-92536 leads to unauthorized access to Personally Identifiable Information (PII) of registered WordPress users. Exposed data includes email addresses, usernames, and registration dates. In environments where WordPress site registration is open to the public, the vulnerability is accessible to unauthenticated attackers, dramatically increasing the potential for mass data harvesting. This could facilitate downstream attacks such as targeted phishing, account takeover, or credential stuffing using the gathered PII.

## Recommendation

Prioritize the following actions to secure vulnerable WordPress installations:

* Immediately update the ProfilePress plugin to the latest version patched against CVE-2026-92536.
* Audit web server access logs for anomalous POST requests to the WordPress registration handler that contain encoded payloads or unexpected query parameters in the reg_nickname and reg_bio fields.
* If an update is not immediately feasible, disable the registration functionality in WordPress settings (users_can_register) to mitigate unauthenticated exploitation.
* Review all pages and posts for usage of the [pp-custom-html] shortcode to identify potentially malicious or unauthorized injections.
