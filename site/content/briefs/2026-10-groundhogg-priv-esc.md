---
title: Privilege Escalation in Groundhogg WordPress Plugin via CVE-2026-92975
slug: 2026-10-groundhogg-priv-esc
description: The Groundhogg WordPress plugin is vulnerable to unauthorized privilege escalation due to insufficient validation of support user account credentials within the create_support_user() function.
date: "2026-10-10T07:51:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:groundhogg:groundhogg:*:*:*:*:*:wordpress:*:*
vendors:
  - Groundhogg
products:
  - Groundhogg (<= 4.8.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Groundhogg WordPress plugin is vulnerable to Privilege Escalation in all versions up to, and including, 4.8.3 via the create_support_user() function.
    confidence_band: high
cves:
  - id: CVE-2026-92975
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92975
iocs:
  - type: email
    value: support@groundhogg.io
  - type: email
    value: help@groundhogg.io
ioc_counts:
  email: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Groundhogg plugin to version > 4.8.3
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92975 advisory
  mitigation_plan:
    - priority: immediate
      action: Remove or sanitize accounts using 'groundhogg' username or support@groundhogg.io / help@groundhogg.io emails
      owner: IT Operations
      addresses: CVE-2026-92975
      evidence: Source documentation of hardcoded credentials.
---

Groundhogg, a CRM and marketing automation plugin for WordPress, contains a high-severity privilege escalation vulnerability (CVE-2026-92975) affecting versions 4.8.3 and earlier. The flaw resides in the `create_support_user()` function, which attempts to identify a support-authorized account by checking if a user's `user_login` matches the hardcoded string 'groundhogg' and if their email matches 'support@groundhogg.io' or 'help@groundhogg.io'. Because the plugin fails to properly validate these attributes against a secure identity provider, an attacker who registers a standard account with the username 'groundhogg' and sets their email address to one of the hardcoded support constants can be automatically promoted to administrator. This promotion occurs when a legitimate site administrator interacts with the plugin's support access functionality. If the triggering administrator possesses `manage_network_options` privileges in a multisite environment, the attacker may also be granted super admin status, leading to full site takeover.

## Impact

Successful exploitation allows a low-privileged user to obtain administrative access to the WordPress instance. This results in the potential for complete site compromise, including the ability to execute arbitrary code, modify site content, exfiltrate sensitive CRM data, and install persistent backdoors. This vulnerability impacts all organizations running Groundhogg versions up to and including 4.8.3.

## Recommendation

1. Upgrade the Groundhogg plugin to the latest patched version immediately.
2. Audit existing user accounts for the username 'groundhogg' and the specified hardcoded email addresses.
3. Restrict or disable open user registration on WordPress instances where the plugin is active to prevent the initial account creation required for exploitation.
